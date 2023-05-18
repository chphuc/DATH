import axios from "../api";
import { message } from "antd";

const login = (values) => {
  return axios
    .post("/auth/signin", {
      username: values.username,
      password: values.password,
      role: "admin",
    })
    .then((res) => {
      console.log(res);
      if (res.data.accessToken) {
        const username = values.username;
        localStorage.setItem("user", JSON.stringify(username));
        localStorage.setItem("admin", JSON.stringify(res.data));
      }
    })
    .catch((err) => {
      console.log(err);
      if (err.response.status === 500) {
        message.error("Internal Server Error");
      }
      if (err.response.status === 401) {
        message.error("Password is wrong");
      }
      if (err.response.status === 404) {
        message.error("User not found");
      }
      if (err.response.status === 403) {
        message.error("You are not authorized to login");
      }
    });
};

const logout = () => {
  localStorage.removeItem("admin");
  localStorage.removeItem("user");
};

const register = (values) => {
  return axios.post("/auth/signup", {
    username: values.username,
    email: values.email,
    password: values.password,
    role: "admin",
  });
};
const getCurrentUser = () => {
  return JSON.parse(localStorage.getItem("admin"));
};

const authService = {
  login,
  logout,
  register,
  getCurrentUser,
};

export default authService;
