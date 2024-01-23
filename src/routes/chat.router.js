import chatDao from "../daos/chat.dao.js";
import { Router } from "express";

const router = Router();

router.get("/", (request, response) => {
    response.render("chat", {
        title: "Chat.",
        fileCss: "../css/styles.css",
    });
});

router.post("/", async (request, response) => {
    const { user, message } = request.body;
    const mesg = { user, message };

    try {
        await chatDao.createMessage(mesg);
        response.status(201).json({
            data: {
                message: "Mensaje creado",
            },
        });
    } catch (e) {
        response.status(500).json({
            error: {
                message: e.message,
            },
        });
    }
});

export default (io) => {
    io.on('connection', (socket) => {
        console.log('Usuario conectado');

        socket.on('chat message', async (data) => {
            console.log(`Mensaje: ${data.message} - Usuario: ${data.user}`);

            try {
                await chatDao.createMessage({ user: data.user, message: data.message });
            } catch (error) {
                console.error('Error al guardar el mensaje en la base de datos:', error);
            }

            io.emit('chat message', data);
        });

        socket.on('disconnect', () => {
            console.log('Usuario desconectado');
        });
    });

    return router;
};

