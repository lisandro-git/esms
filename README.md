![built-with-love](img/built-with-love.svg?style=centerme)
![works-on-linux](img/works-on-linux.svg?style=centerme)
![gluten-free](img/gluten-free.svg?style=centerme)
![works-on-my-machine](img/works-on-my-machine.svg?style=centerme)
![60-of-the-time-works-every-time](img/60-of-the-time-works-every-time.svg?style=centerme)

# π©Preamble
This is a pure Rust multi-client encrypted messaging system, also known as Edode's Secured Messaging System.
It is an end-to-end(s) communication system using a AES256-CBC encryption model. Every single piece of message
(including the password verification part) is encrypted. Every message goes through the server, and the server sends back
every received messages to all the clients connected and authenticated.

# π» Technos
- **AES256-CBC**

# β Changelog
> Server | Client
>> - Modified message transmission protocol to include the username of the sender
>> - Improved the username implementation

# π§ͺ Miscellaneous
- Server's password : 12345678901234567890123556789011
    - Can be changed in "chat/server/main.rs" variable : PASS
    - Has to be 32 bit long to work
  
# π Upcoming
- Code improvement and enhancement of memory management
- UI 
 
# π Features
- **AES256-CBC password encryption**
- **Multi-client chat**
- **Pure Rust**

# π Authors
- **[Edode](https://www.github.com/lisandro-git)**

# π License
- **[GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/)**
