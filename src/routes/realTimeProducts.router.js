import { Router } from 'express';
import productsDao from '../daos/products.dao.js';


const router = Router();

router.get("/", (request, response) => {
    response.render("realTimeProducts", {
        title: "Agregar productos en tiempo real.",
        fileCss: "../css/styles.css"
    });
});

router.post("/", async (request, response) => {
    const {
        title,
        description,
        price,
        thumbnail,
        code,
        stock,
        status,
        category
    } = request.body;
    
    const product = { title, description, price, thumbnail, code, stock, status, category };

    try {
        await productsDao.createProduct(product);
        response.status(201).json({
            data: {
                message: "Producto creado",
            }
        });
    } catch (e) {
        response.status(500).json({
            error: {
                message: e.message,
            }
        });
    }

});

export default (io) => {
    io.on("connection", async socket => {
        console.log("Cliente conectado");

        socket.on("product_send", async (data) => {
            try {
                const product = {
                    title: data.title,
                    description: data.description,
                    price: Number(data.price),
                    thumbnail: data.thumbnail,
                    code: data.code,
                    stock: Number(data.stock),
                    status: data.status,
                    category: data.category
                };
                await productsDao.createProduct(product);
                io.emit("products", await productsDao.getAllProducts());
                console.log(product)
                console.log(productsDao.getAllProducts())
            } catch (error) {
                console.log(error)
            }
        });
        socket.emit("products", await productsDao.getAllProducts());

        socket.on("delete_product", async (_id) => {
            await productsDao.deleteProduct(_id);
            io.emit("products", await productsDao.getAllProducts());
        });
    });
    return router;
};


