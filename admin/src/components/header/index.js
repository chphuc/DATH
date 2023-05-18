import { Layout, Typography, Dropdown, Menu, Space, Divider } from "antd";
import React, { memo, useEffect, useState } from "react";
import { UserOutlined, LogoutOutlined } from "@ant-design/icons";
import "./style.css";
import authService from "../../services/Auth";
import Notification from "../notification";

function Header() {
  const [username, setUsername] = useState(localStorage.getItem("user"));

  useEffect(() => {
    setUsername(username?.substring(1, username.length - 1));
    console.log(username, "hihi");
  }, []);
  console.log(username);

  const menu = (
    <Menu
      items={[
        {
          key: "0",
          label: (
            <>
              <div>
                <p>Logged in as: {username}</p>
              </div>
              <Divider />
              <a
                onClick={() => {
                  authService.logout();
                }}
                href="/login"
              >
                <Space>
                  <LogoutOutlined />
                  Logout
                </Space>
              </a>
            </>
          ),
        },
      ]}
    />
  );

  return (
    <Layout.Header
      theme="light"
      style={{
        backgroundColor: "#367e62",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        zIndex: "2",
      }}
      className="header"
    >
      <Typography.Title>
        {" "}
        <img
          className="img-header"
          src="https://cdn.shopify.com/s/files/1/0591/1350/4958/files/3.png?v=1628328728&width=360"
        />
      </Typography.Title>
      <Space size={"large"}>
        <Notification />
        <Dropdown overlay={menu}>
          <UserOutlined style={{ color: "black", fontSize: "16px" }} />
        </Dropdown>
      </Space>
    </Layout.Header>
  );
}

export default memo(Header);
