![built-with-love](img/built-with-love.svg?style=centerme)
![works-on-linux](img/works-on-linux.svg?style=centerme)
![no-ragrets](img/no-ragrets.svg?style=centerme)
![gluten-free](img/gluten-free.svg?style=centerme)
![60-of-the-time-works-every-time](img/60-of-the-time-works-every-time.svg?style=centerme)
![works-on-my-machine](img/works-on-my-machine.svg?style=centerme)

# 🚩Preamble
This is a pure Rust multi-client encrypted messaging system, also known as Edode's Secured Messaging System.
It is an end-to-end(s) communication system using a AES256-CBC encryption model. Every single piece of message
(including the password verification part) is encrypted. Every message goes through the server, and the server sends back
every received messages to all the clients connected and authenticated.

# ✅ Changelog
> Server
>> - Decryption of the received message
>> - Encryption of the message to be send to the clients
> 
> Client
>> - Encryption of the message
>> - Decryption of the other clients message

# 📃 Upcoming
- Previous commit-related bug 
- UI 
 
# 📍 Features
- **AES256-CBC password encryption**
- **Multi-client chat**
- **Pure Rust**

# 🖊 Authors
- **[Edode](https://www.github.com/lisandro-git)**

# 📜 License
- **[GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/)**
