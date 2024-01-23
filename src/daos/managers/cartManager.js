import fs from 'fs';

class CartManager {
    constructor() {
        this.path = "./src/carts.json";

        if (fs.existsSync(this.path)) {
            try {
                this.getCarts();
            } catch (error) {
                console.error(error);
            }
        } else {
            this.carts = [];
            this.saveFile();
        }
    }

    async saveFile() {
        try {
            await fs.promises.writeFile(
                this.path,
                JSON.stringify(this.carts, null, "\t"),
                "utf-8"
            );
            console.log("Carrito guardado correctamente.");
        } catch (error) {
            console.error(error);
        }
    }

    async getCarts() {
        try {
            const data = fs.readFileSync(this.path, "utf-8");
            this.carts = data.trim() === "" ? [] : JSON.parse(data);
            return this.carts;
        } catch (error) {
            console.error("Error al recuperar los carritos.");
            console.error(error);
        }
    }

    async addCart() {
        let cid;
        do {
            cid = this.carts.length + 1;
        } while (this.carts.some(cart => cart.cid === cid));

        const newCart = new Cart(cid, []);

        this.carts.push(newCart);

        await this.saveFile();

        return cid;
    }

    getCartById(cid) {
        const searchedCart = this.carts.find((cart) => cart.cid === cid);

        if (!searchedCart) {
            return "El carrito no existe";
        } else {
            return searchedCart;
        }
    }


    async addProductToCart(cid, pid) {
        const cartIndex = this.carts.findIndex(cart => cart.cid === cid);
        const cartToUse = this.carts[cartIndex];

        if (!cartToUse) {
            return console.log("El carrito no existe.");
        }

        const productIndex = cartToUse.products.findIndex(element => element.product === pid);

        if (productIndex === -1) {
            cartToUse.products.push({ "product": pid, "cuantity": 1 });
        } else {
            cartToUse.products[productIndex].cuantity += 1;
        }

        await this.saveFile();
        return console.log("Producto agregado al carrito.");
    }
}


class Cart {
    constructor(cid, products) {
        this.cid = cid;
        this.products = products;
    }
}

export { CartManager, Cart };

