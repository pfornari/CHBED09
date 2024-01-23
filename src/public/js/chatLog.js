function initChat() {
    const socket = io();
    const messageInput = document.getElementById('message-input');
    const userInput = document.getElementById('username-input');
    const sendButton = document.getElementById('send-button');
    const chatMessages = document.getElementById('chat-messages');

    sendButton.addEventListener('click', () => {
        sendMessage();
    });

    socket.on('chat message', (data) => {
        displayMessage(data);
    });

    function sendMessage() {
        const message = messageInput.value;
        const user = userInput.value;
        if (message.trim() !== '' && user.trim() !== '') {
            const data = { user, message };
            socket.emit('chat message', data);
            messageInput.value = '';
        }
    }

    function displayMessage(data) {
        const li = document.createElement('li');
        li.textContent = `${data.user}: ${data.message}`;
        chatMessages.appendChild(li);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initChat();
});

