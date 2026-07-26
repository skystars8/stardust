

![1](https://github.com/user-attachments/assets/661e24e6-bb92-4a49-9f12-1401bd5e590f)


# 8- Rust simple encryption


simple encryption no external key, no requested password. It only asks for a file name, and then processes the file. Overwrites the file, so for critical data make sure copy of file is stored somewhere. Tested on 500mb text file, seems to encrypt and decrypt fine. 



The script takes one argument, which is the name of the file to encrypt. It reads the contents of the file, applies the built-in encryption key to 
each byte of the file using the XOR operator, and then overwrites the original file with the encrypted contents.

To decrypt the file, you can simply run the script again with the same filename,
and it will apply the same "key" to the encrypted file to recover the original contents.


 
