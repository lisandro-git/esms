![built-with-love](img/built-with-love.svg?style=centerme)
![works-on-linux](img/works-on-linux.svg?style=centerme)
<<<<<<< HEAD
=======
![gluten-free](img/gluten-free.svg?style=centerme)
![60-of-the-time-works-every-time](img/60-of-the-time-works-every-time.svg?style=centerme)
>>>>>>> 34286e2f9e53960f6cf8b37f1ac2cf851e446df8
![works-on-my-machine](img/works-on-my-machine.svg?style=centerme)
![60-of-the-time-works-every-time](img/60-of-the-time-works-every-time.svg?style=centerme)
![gluten-free](img/gluten-free.svg?style=centerme)

# 🚩Preamble
This is a pure Rust multi-client encrypted messaging system, also known as Edode's Secured Messaging System.
It is an end-to-end(s) communication system using a AES256-CBC encryption model. Every single piece of message
(including the password verification part) is encrypted. Every message goes through the server, and the server sends back
every received messages to all the clients connected and authenticated.

# 💻 Technos
- **AES256-CBC**

# ✅ Changelog
<<<<<<< HEAD
> Server
>> - The server send the message to all but not for the original sended

# 🧪 Miscellaneous
- Server's password : 12345678901234567890123556789011
    - Can be changed in "chat/server/main.rs" variable : PASS
    - Has to be 32 bit long to work
=======
> Server | Client
>> - Addressed multiple bugs regarding the encryption/decryption of the messages
>> - Improved/cleaned the code
>> - Server's password : 12345678901234567890123556789011
>>>>>>> 34286e2f9e53960f6cf8b37f1ac2cf851e446df8

# 📃 Upcoming
- Code improvement and enhancement of memory management
- UI 
 
# 📍 Features
- **AES256-CBC password encryption**
- **Multi-client chat**
- **Pure Rust**

# 🖊 Authors
- **[Edode](https://www.github.com/lisandro-git)**

# 📜 License
- **[GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/)**
