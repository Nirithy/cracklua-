import base64
import zlib
import unicodedata
import os

# ==========================================
# 工具函数：字符串解密算法 (Layer 2 核心)
# ==========================================

def algo_decrypt_string(payload_bytes):
    """
    int x=size-1;
    int v5=b.charAt(0)^x;
    """
    b = bytearray(payload_bytes)
    size_minus_1 = len(b)
    
    if size_minus_1 == 0:
        return b

    x = size_minus_1
    v5 = b[0] ^ x
    v6 = x + v5
    
    for i in range(size_minus_1):
        v8 = x % 255
        x += v6
        original_byte = b[i]
        b[i] = original_byte ^ v8
        
    return b

def is_valid_utf8_text(data_bytes):
    """
    验证解密后的数据是否为合法的 UTF-8 文本
    防止误伤非字符串的字节码指令
    """
    if not data_bytes:
        return True

    try:
        decoded_str = data_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return False

    # 检查控制字符，剔除乱码
    for char in decoded_str:
        if unicodedata.category(char) == 'Cc':
            if char not in ('\r', '\n', '\t'):
                return False
    return True

# ==========================================
# 第一阶段：容器解密 (Base64 + XOR + Zlib)
# ==========================================

def stage1_loader_decrypt(filename):
    print(f"[*] Stage 1: 正在读取并解压 {filename} ...")
    
    if not os.path.exists(filename):
        print(f"错误: 找不到文件 {filename}")
        return None

    with open(filename, "rb") as fp:
        buffer = fp.read()

    # 1. 修正头部并 Base64 解码
    # buffer=b'H'+buffer[1:]
    if len(buffer) > 0:
        buffer = b'H' + buffer[1:]
    
    try:
        buffer = base64.b64decode(buffer)
    except Exception as e:
        print(f"Base64 解码失败: {e}")
        return None

    # 2. 滚动异或解密
    # init=init^i 这种算法
    init = 0
    buffer_dec1 = bytearray()
    for i in buffer:
        init = init ^ i
        buffer_dec1.append(init)
    
    # 3. Zlib 解压
    # buffer_dec2=b'\x78'+buffer_dec1[1:]
    if len(buffer_dec1) > 1:
        # 手动修复 zlib 头 (78 = Deflate)
        buffer_dec2 = b'\x78' + buffer_dec1[1:]
        try:
            decompressed = zlib.decompress(buffer_dec2)
        except zlib.error as e:
            print(f"Zlib 解压失败: {e}")
            return None
    else:
        print("数据过短，无法解压")
        return None

    # 4. 修正 Lua 头部
    # f.write(b'\x1b'+decompressed[1:])
    # 我们这里返回 bytearray 方便下一阶段直接在内存修改
    if len(decompressed) > 0:
        final_bytecode = bytearray(b'\x1b' + decompressed[1:])
        return final_bytecode
    
    return None

# ==========================================
# 第二阶段：字节码混淆修复 (String Deobfuscation)
# ==========================================

def stage2_bytecode_patch(data):
    print(f"[*] Stage 2: 正在扫描并修复混淆字符串 (总大小: {len(data)} bytes)...")
    
    length = len(data)
    modified_count = 0
    
    # 跳过 Lua 头部 (Signature + Header)，防止误改配置信息
    i = 0
    if data.startswith(b'\x1bLua'):
        i = 30 

    while i < length:
        # 特征扫描: 04 (String Type in Lua 5.1)
        if data[i] == 0x04:
            if i + 1 >= length:
                break
            
            size_byte = data[i+1]
            payload_len = size_byte - 1
            
            # 长度合理性校验
            if payload_len > 0 and (i + 2 + payload_len) <= length:
                payload_start = i + 2
                payload_end = payload_start + payload_len
                original_payload = data[payload_start:payload_end]
                
                # 尝试解密
                decrypted_candidate = algo_decrypt_string(original_payload)
                
                # 智能校验: 是否为有效文本 (支持中文)
                if is_valid_utf8_text(decrypted_candidate):
                    # 打印预览
                    try:
                        dec_str = decrypted_candidate.decode('utf-8')
                        preview = dec_str if len(dec_str) < 25 else dec_str[:25] + "..."
                        # 仅在调试时取消下面注释，防止刷屏
                        # print(f"    [Patch] Offset {i:04X}: '{preview}'")
                    except:
                        pass

                    # 应用修改
                    data[payload_start:payload_end] = decrypted_candidate
                    modified_count += 1
                    
                    # 跳过已处理区域
                    i += 2 + payload_len
                    continue
        
        i += 1
        
    print(f"[*] Stage 2 完成: 共恢复了 {modified_count} 个字符串 (含中文)")
    return data

# ==========================================
# 主程序
# ==========================================

if __name__ == "__main__":
    input_file = "main.lua"
    output_file = "main_decoded.lua"

    # 1. 执行第一层解密
    bytecode = stage1_loader_decrypt(input_file)
    
    if bytecode:
        # 2. 执行第二层解密 (无需保存中间文件，直接内存操作)
        final_data = stage2_bytecode_patch(bytecode)
        
        # 3. 保存最终结果
        with open(output_file, "wb") as f:
            f.write(final_data)
        
        print(f"\n[Success] 所有操作完成！")
        print(f"输出文件: {output_file}")
        print("现在你可以尝试使用 luadec 反编译这个文件了。")
