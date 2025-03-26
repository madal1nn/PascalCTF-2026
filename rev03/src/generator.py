FLAG = "VMs_4r3_d14bol1c4l_3n0ugh_d0nt_y0u_th1nk"
OP = {
    "VM_OP_RET": 0x0,
    "VM_OP_ADD": 0x1,
    "VM_OP_SUB": 0x2,
    "VM_OP_MOD": 0x3,
    "VM_OP_MOV": 0x4,
    "VM_OP_READ": 0x5,
    "VM_OP_CMP_JMP": 0x6,
}

def generate():
    s = b""
    for i in range(len(FLAG)):
        # READ CHAR
        s += bytes([OP["VM_OP_READ"]])
        s += int.to_bytes(i, 4, 'little')

        # MOV IDX
        s += bytes([OP["VM_OP_MOV"]])
        s += int.to_bytes(i+1, 4, 'little')
        s += bytes([i])

        # MOD IDX 2
        s += bytes([OP["VM_OP_MOD"]])
        s += int.to_bytes(i+1, 4, 'little')
        s += bytes([2])

        # JMP IF EVEN
        s += bytes([OP["VM_OP_CMP_JMP"]])
        s += int.to_bytes(i+1, 4, 'little')
        s += bytes([6 * 2])

        # ADD FLAG -i
        s += bytes([OP["VM_OP_SUB"]])
        s += int.to_bytes(i, 4, 'little')
        s += bytes([i])

        # JMP AWAY
        s += bytes([OP["VM_OP_CMP_JMP"]])
        s += int.to_bytes(1023, 4, 'little')
        s += bytes([6])

        # ADD FLAG +i
        s += bytes([OP["VM_OP_ADD"]])
        s += int.to_bytes(i, 4, 'little')
        s += bytes([i])

    # READ newline
    s += bytes([OP["VM_OP_READ"]])
    s += int.to_bytes(len(FLAG), 4, 'little')

    # MOV 0
    s += bytes([OP["VM_OP_MOV"]])
    s += int.to_bytes(len(FLAG), 4, 'little')
    s += bytes([0])

    # RET
    s += bytes([OP["VM_OP_RET"]])

    with open("code.pascal", "wb") as f:
        f.write(s)
    
if __name__ == "__main__":
    generate()
    print("code.pascal generated successfully.")