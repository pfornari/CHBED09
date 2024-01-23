import fs from 'fs'

class ProductManager {
    constructor() {
        this.path = "./src/products.json";

        if (fs.existsSync(this.path)) {
            try {
                this.getProducts();
            } catch (error) {
                console.log(error);
            }
        } else {
            this.products = [];
            this.saveFile();
        }
    }

    async saveFile() {
        try {
            await fs.promises.writeFile(
                this.path,
                JSON.stringify(this.products, null, "\t"),
                "utf-8"
            );
            console.log("Archivo guardado correctamente.");
        } catch (error) {
            console.log(error);
        }
    }

    async getProducts() {
        try {
            const data = fs.readFileSync(this.path, "utf-8");
            if (data.trim() === "") {
                this.products = [];
            } else {
                this.products = JSON.parse(data);
            }
            return this.products;
        } catch (error) {
            console.log("Error al recuperar productos.");
            console.log(error);
        }
    }

    async addProduct(product) {
        if (
            !product ||
            !product.title ||
            !product.description ||
            !product.price ||
            !product.code ||
            !product.stock ||
            !product.status ||
            !product.category
        ) {
            return "Faltan datos para agregar el producto.";
        }

        const existingProduct = this.products.find((p) => p.code === product.code);

        if (existingProduct) {
            console.log(
                "El código de producto ya existe. No se agregará el producto."
            );
            return;
        }

        if (!product.id) {
            product.id = this.products.length + 1;
        }
        const existingProductId = this.products.find((existingProduct) => existingProduct.id === product.id);
        
        if (existingProductId) {
            product.id = this.products.length + 2;
        }
        
        this.products.push(product);

        await this.saveFile();
    }

    getProductById(id) {
        const searchedProduct = this.products.find((product) => product.id === id);

        if (!searchedProduct) {
            return "El producto no existe";
        } else {
            return searchedProduct;
        }
    }

    async deleteProduct(id) {
        const productToDelete = this.products.find((p) => p.id == id);

        if (productToDelete) {
            const newArray = this.products.filter((p) => p.id != id);

            this.products = newArray;
            await this.saveFile();
        } else {
            console.log("Error al eliminar producto");
        }
    }

    async updateProduct(id, updatedProduct) {
        const index = this.products.findIndex((product) => product.id === id);

        if (index === -1) {
            return console.log("El producto no existe.");
        } else {
            const { id, ...restOfProduct } = updatedProduct;
            this.products[index] = { ...this.products[index], ...restOfProduct };
            await this.saveFile();
            console.log("El producto fue actualizado.");
        }
    }
}

class Product {
    constructor(title, description, price, thumbnail, code, stock, status, category, id) {
        this.title = title;
        this.description = description;
        this.price = price;
        this.thumbnail = thumbnail;
        this.code = code;
        this.stock = stock;
        this.status = status;
        this.category = category;
        this.id = id;
    }
}

// Tests

/*async function lanzarTests() {
    const productManager = new ProductManager();

    console.log("Agregando producto de prueba...");
    await productManager.addProduct(
        new Product(
            "Product 1",
            "Este es un producto de prueba",
            200,
            "Sin imagen.",
            "abc123",
            25,
            true,
            "category1",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 2",
            "Este es un producto de prueba 2",
            290,
            "Sin imagen.",
            "lkc141",
            36,
            true,
            "category2",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 3",
            "Este es un producto de prueba 3",
            450,
            "Sin imagen.",
            "bgd145",
            40,
            true,
            "category3",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 4",
            "Este es un producto de prueba 4",
            290,
            "Sin imagen.",
            "jhg653",
            16,
            true,
            "category2",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 5",
            "Este es un producto de prueba 5",
            290,
            "Sin imagen.",
            "ljh563",
            36,
            true,
            "category2",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 6",
            "Este es un producto de prueba 6",
            253,
            "Sin imagen.",
            "vyc512",
            54,
            true,
            "category1",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 7",
            "Este es un producto de prueba 7",
            650,
            "Sin imagen.",
            "jfs253",
            61,
            true,
            "category3",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 8",
            "Este es un producto de prueba 8",
            420,
            "Sin imagen.",
            "pek665",
            27,
            true,
            "category1",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 9",
            "Este es un producto de prueba 9",
            220,
            "Sin imagen.",
            "lkj221",
            36,
            true,
            "category3",
        )
    );
    await productManager.addProduct(
        new Product(
            "Product 10",
            "Este es un producto de prueba 10",
            290,
            "Sin imagen.",
            "ghb245",
            42,
            true,
            "category1",
        )
    );

}

lanzarTests()*/

export default ProductManager ;
export { Product } ;