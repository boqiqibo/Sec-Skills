---
name: flutter-ssl-analysis
description: |
  Analyze Flutter Android ARM64 libflutter.so to locate BoringSSL SSL_write/SSL_read function addresses and generate Frida SSL bypass scripts. Use this skill when the user mentions Flutter SSL analysis, BoringSSL function location, ecapture SSL hooking, libflutter.so reverse engineering, or needs to bypass Flutter SSL certificate verification.
---

# Flutter SSL Analysis Skill

This skill helps locate BoringSSL SSL_write/SSL_read function addresses in Flutter Android ARM64 libflutter.so (stripped) and generate Frida scripts for SSL bypass.

## Key Concept: IDA Address vs File Offset

ecapture's `--ssl_write_addr` / `--ssl_read_addr` require **ELF file offset**, not IDA virtual address.

### ⚠️ 重要：不要假设固定偏移量

**错误做法**：假设 `file_offset = IDA_VA - 0x1000`
- 这个 0x1000 偏移量是假设值，不同版本的 libflutter.so 可能有不同的段布局
- 直接使用假设值会导致 ecapture hook 失败

### 正确计算方法

**方法一：使用 IDA Python API（推荐）**
```python
import idaapi

# 获取准确的文件偏移
ida_va = 0xYOUR_VA  # 替换为实际地址
file_offset = idaapi.get_fileregion_offset(ida_va)
print(f"IDA VA: {hex(ida_va)}")
print(f"File Offset: {hex(file_offset)}")
```

**方法二：读取 ELF PT_LOAD 段信息**
```python
import idaapi

def get_file_offset(va):
    """
    通过遍历 PT_LOAD 段计算文件偏移
    公式: file_offset = VA - VirtAddr + FileOffset
    """
    for seg in idautils.Segments():
        seg_ea = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        if seg_ea <= va < seg_end:
            # 获取段的文件偏移
            seg_file_offset = idaapi.get_fileregion_offset(seg_ea)
            return va - seg_ea + seg_file_offset
    return None
```

**方法三：使用 readelf 命令验证**
```bash
# 查看 PT_LOAD 段布局
readelf -l libflutter.so | grep LOAD

# 输出示例：
#   LOAD           0x000000 0x00000000 0x00000000 0xXXXXXX 0xXXXXXX R
#   LOAD           0xXXXXXX 0xXXXXXX 0xXXXXXX 0xXXXXXX 0xXXXXXX R E
# 
# 其中：FileOffset = 第一列, VirtAddr = 第三列
# file_offset = IDA_VA - VirtAddr + FileOffset
```

### ssl_read_inner_offset 计算

`ssl_read_inner_offset` 是相对偏移（BL_VA - SSL_read_VA），两地址在同一段内相减，偏差自动消除：
```
ssl_read_inner_offset = BL_VA - SSL_read_entry_VA
```
**无需转换为文件偏移**，ecapture 直接使用这个相对偏移值。

## Known Conditions

- Architecture: ARM64, IDA base=0x0
- Flutter uses embedded BoringSSL (not system libssl)
- Call chain: SSLFilter::ProcessAllBuffers → SSL_write/SSL_read
- SSLFilter member layout:
  - `ssl_` @ offset 0x18
  - `socket_side_` @ offset 0x20
  - `buffers_[0..3]` starting from offset 0x30, 8 bytes each

---

## Part 1: Locating SSL_write/SSL_read Functions

### Step 1: Find __errno PLT

Use `mcp_ida-pro-mcp_imports` or `mcp_ida-pro-mcp_list_funcs(filter="*errno*")` to find `.__errno` address.

### Step 2: Find ERR_clear_system_error

Use `mcp_ida-pro-mcp_xrefs_to` to find all callers of `.__errno`.

Filter criteria: Function body ≤ 4 instructions, only calls `.__errno` and `STR WZR, [X0]`.

### Step 3: Find ssl_reset_error_state

Use `mcp_ida-pro-mcp_xrefs_to` to find callers of `ERR_clear_system_error`.

Filter criteria:
- Function body ≤ 10 instructions (~28 bytes)
- Contains `STR WZR, [X0, #0xXX]` (clears ssl->s3->rwstate)
- Calls `ERR_clear_error` (another helper function)
- Calls `ERR_clear_system_error`

### Step 4: Find All Callers of ssl_reset_error_state

Use `mcp_ida-pro-mcp_xrefs_to(ssl_reset_error_state_addr)`, typically 3–5 callers.

### Step 5: Identify SSL_write

From callers, find:
- Smaller function (200–350 bytes)
- After calling `ssl_reset_error_state`, checks if `[ssl, #0xXX]` is nullptr (CBZ, corresponding to `do_handshake` check)
- Contains BLR (vtable indirect call to `write_app_data`)
- Has an embedded loop calling another medium-sized function (SSL_do_handshake)

### Step 6: Identify SSL_read

From callers, find:
- Larger function (> 1000 bytes)
- After calling `ssl_reset_error_state`, enters complex switch/loop (has jump table `jpt_xxx`)
- Function body corresponds to `ssl_read_impl` (inlined SSL_peek and ssl_read_impl)

### Step 7: Verify via Call Points

Search for `ProcessAllBuffers` function (contains `"Out-of-bounds internal buffer"` or `"SecureSocket"` string references):
- Find instructions a few lines before `BL SSL_write_candidate`
- Verify: `LDR X0, [SSLFilter, #0x18]` (ssl_), `LDR Xn, [SSLFilter, #0x38]` (buffers_[kWritePlaintext])
- Similarly verify `SSL_read_candidate` uses `[SSLFilter, #0x30]` (buffers_[kReadPlaintext])

### Step 8: Confirm Line Numbers

Decompile SSL_write candidate function, find `ERR_put_error` call (`sub_70FXXX`), its W3 parameter (immediate) should approximately equal the line number in BoringSSL ssl_lib.cc for SSL_write (~940–980).

---

### Step 9: Find ssl_read_inner_offset

**Goal**: Find the BL instruction offset inside SSL_read that calls the memcpy wrapper stub, used for ecapture inner probe.

**Wrapper stub characteristics** (only 2 instructions):
```asm
MOV X2, Xreg    ; Put size into X2 (ARM64 memcpy 3rd parameter)
B .memcpy       ; Tail call to real memcpy
```

Different versions use different size_reg: old version (de8c7af5) uses `X24`, new version uses `X22`.

**Locate this BL in SSL_read** (at the end of SSL_read success path):
```asm
; Identify characteristic sequence (example from new libflutter.so):
LDR X9, [X8, #0x88]     ; X9 = ssl3_state->rbuf.len (readable bytes)
MOV W10, Wn             ; W10 = num (user requested bytes, from SSL_read 3rd param)
CMP X9, Wn, UXTW        ; Compare avail vs num
CSEL Xn, X9, X10, CC    ; Xn = min(avail, num) ← this is size_reg
CBZ Xn, label           ; If 0 bytes, skip
LDR X1, [X8, #0x80]     ; X1 = ssl3_state->rbuf.buf (plaintext source, C++ heap)
MOV X0, Xn              ; X0 = destination buffer
BL sub_memcpy_stub      ; ← inner probe is here
```

**Steps**:
1. Use `mcp_ida-pro-mcp_callees(ssl_read_va)` to list all functions called by SSL_read.
2. Filter functions with size ≤ 8 bytes (2 instructions), disassemble each to confirm `MOV X2, Xreg; B .memcpy`.
3. Use `mcp_ida-pro-mcp_xrefs_to(stub_addr)` to find the BL instruction address calling it from inside SSL_read (`BL_VA`).
4. Confirm the characteristic sequence by disassembling around BL_VA (LDR X1 = plaintext src, CSEL = size).

**Calculation**:
```
ssl_read_inner_offset = BL_VA - SSL_read_entry_VA
```
No need to subtract 0x1000 (relative offset, bias cancels out).

---

## Part 2: SSL Bypass Script Generation

### Step 1: Find ssl_client String

Use MCP to search for string "ssl_client" and get the function address containing this string.

### Step 2: Get First 12 Bytes

Return the first 12 bytes of bytecode from that function, e.g.:
```
var pattern = "ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48"
```

### Step 3: Update Frida Script

Replace the bytecode in the Frida script based on whether the .so is 32-bit or 64-bit:
- 64-bit: Update `hookFlutter_64()` function's pattern
- 32-bit: Update `hookFlutter_32()` function's pattern

---

## Output Format

```
SSL_write IDA VA : 0xXXXXXX
SSL_read IDA VA : 0xXXXXXX
ssl_read_inner_offset : 0xXXX (= BL_VA - SSL_read_entry_VA)

# 计算文件偏移（使用 IDA Python）：
import idaapi
ssl_write_file_offset = idaapi.get_fileregion_offset(SSL_write_IDA_VA)
ssl_read_file_offset = idaapi.get_fileregison_offset(SSL_read_IDA_VA)

# ecapture 实际传参：
--ssl_write_addr 0xXXXXXX (file offset, 通过 get_fileregion_offset 计算)
--ssl_read_addr 0xXXXXXX (file offset, 通过 get_fileregion_offset 计算)
--ssl_read_inner_offset 0xXXX (相对偏移，直接使用 BL_VA - SSL_read_entry_VA)
```

### 验证步骤

1. **验证文件偏移计算正确性**：
```python
# 在 IDA Python 中执行
import idaapi
va = 0xYOUR_VA
offset = idaapi.get_fileregion_offset(va)
print(f"VA: {hex(va)} -> File Offset: {hex(offset)}")
```

2. **验证 ssl_read_inner_offset**：
```python
# 确认 BL 指令在 SSL_read 函数内部
bl_va = 0xYOUR_BL_VA
ssl_read_va = 0xYOUR_SSL_READ_VA
inner_offset = bl_va - ssl_read_va
print(f"ssl_read_inner_offset: {hex(inner_offset)}")
```

---

## Reference Files

- [frida-ssl-bypass.js](references/frida-ssl-bypass.js) - Frida SSL bypass script template
