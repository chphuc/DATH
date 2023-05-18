import React, { useState } from "react";
import { Typography, Button, Form, Input, Card } from "antd";
import { LockOutlined, UserOutlined } from "@ant-design/icons";
import UI from "./UI";
// import axios from '../../api'
import authService from "../../services/Auth";
import { useNavigate } from "react-router-dom";

const { Title } = Typography;
function Login() {
  const [form] = Form.useForm();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  const onFinish = async (values) => {
    try {
      await authService.login(values).then(
        () => {
          if (authService.getCurrentUser()) {
            navigate("/");
          }
        },
        (err) => {
          console.log(err);
        }
      );
    } catch (err) {
      console.log(err);
    }
  };
  return (
    <div className="login-container">
      <UI />
      <div className="right-container">
        <Card style={{ margin: "100px" }}>
          <Title style={{ textAlign: "center" }} level={3}>
            Welcome
          </Title>
          <Form
            form={form}
            name="normal_login"
            className="login-form"
            initialValues={{ remember: true }}
            onFinish={onFinish}
          >
            <Form.Item
              name="username"
              rules={[
                { required: true, message: "Please input your Username!" },
              ]}
            >
              <Input
                value={username}
                minLength={6}
                maxLength={30}
                onChange={(e) => {
                  setUsername(e.target.value);
                }}
                prefix={<UserOutlined className="site-form-item-icon" />}
                placeholder="Username"
              />
            </Form.Item>
            <Form.Item
              name="password"
              rules={[
                { required: true, message: "Please input your Password!" },
              ]}
            >
              <Input.Password
                prefix={<LockOutlined className="site-form-item-icon" />}
                minLength={8}
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                }}
                placeholder="Password"
              />
            </Form.Item>
            <Form.Item>
              <a style={{ float: "left  ", color: "#7DA863" }} href="/register">
                Register now!
              </a>

              <a
                style={{ float: "right", color: "#7DA863" }}
                className="login-form-forgot"
                href="/forgot-password"
              >
                Forgot password
              </a>
            </Form.Item>

            <Form.Item>
              <Button
                style={{
                  width: "100%",
                  backgroundColor: "#7DA863",
                  borderRadius: "10px",
                  border: "1px solid #7DA863",
                  // color: 'white'
                }}
                type=""
                htmlType="submit"
                className="login-form-button"
              >
                Sign In
              </Button>
            </Form.Item>
          </Form>
        </Card>
      </div>
    </div>
  );
}

export default Login;
