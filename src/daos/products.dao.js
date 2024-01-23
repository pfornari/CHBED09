import mongoose from "mongoose";
import { productModel } from "./models/products.model.js";

class ProductDao {
  async getAllProducts(limit = 10, page = 1, query, sort) {
    try {
      limit = parseInt(limit) || 10;
      page = parseInt(page) || 1;

      let consulta = {};

      if (query) {
        const [campo, valor] = query.split(":");
        if (campo && valor) {
          consulta[campo] = valor;
        }
      }

      const options = {
        limit,
        page,
        sort: sort ? { price: Number(sort) } : {},
      };

      const result = await productModel.paginate(consulta, options);
      return result;
    } catch (error) {
      console.error("Error en getAllProducts:", error);
      throw error; 
    }
  }

  async getProductById(_id) {
    try {
      const objectId = new mongoose.Types.ObjectId(_id);
      return await productModel.findById(objectId);
    } catch (error) {
      throw new Error(`Error while fetching product by ID: ${error.message}`);
    }
  }

  async createProduct(product) {
    try {
      return await productModel.create(product);
    } catch (error) {
      throw new Error(`Error while creating product: ${error.message}`);
    }
  }

  async updateProduct(_id, product) {
    try {
      const objectId = new mongoose.Types.ObjectId(objectId);
      return await productModel.findByIdAndUpdate(objectId, product);
    } catch (error) {
      throw new Error(`Error while updating product: ${error.message}`);
    }
  }

  async deleteProduct(_id) {
    try {
      const objectId = new mongoose.Types.ObjectId(objectId);
      return await productModel.findByIdAndDelete(objectId);
    } catch (error) {
      throw new Error(`Error while deleting product: ${error.message}`);
    }
  }
}
export default new ProductDao();
