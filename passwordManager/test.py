b = (255).to_bytes(1, 'little')
bar = bytearray(b)
bar[0] = 123
b = bytes(bar)
print(b.hex())