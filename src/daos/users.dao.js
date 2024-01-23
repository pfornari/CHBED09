import { userModel } from "./models/user.model.js";

class UserDao {
  async getUserByEmail(email) {
    try {
      return await userModel.findOne({ email });
    } catch (error) {
      throw new Error(`Error while fetching user by email: ${error.message}`);
    }
  }
}

export default new UserDao();
