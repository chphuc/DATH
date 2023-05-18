E-COMMERCE PROGRAMMING INTERGRATION PROJECT
===========

This e-commerce website represents the culmination of my work in the `PROGRAMMING INTERGRATION PROJECT` course, showcasing a comprehensive range of functionalities tailored to meet the needs of both sellers and customers. As a seller, you will have the ability to efficiently manage products, orders, user information, and access sales statistics, providing you with valuable insights to drive business growth. For customers, the website offers a seamless shopping experience, ensuring a user-friendly interface and convenient features to enhance their satisfaction.

## Features
- User authentication: Secure login and logout functionality.
- Account creation: Users can easily create new accounts to access the platform.
- Product search: Efficient search functionality to find desired - products.
- Product management (Admin): Admins have the ability to manage and update product listings.
- Order management (Admin): Admins can efficiently handle and track customer orders.
- User information management (Admin): Admins can manage and update user information as necessary.
- Revenue statistics: Comprehensive statistics and insights into - sales revenue.
- Product viewing: Users can view detailed information about - products.
- Cart management: Users can add, remove, and modify items in their shopping carts.
- Order placement: Users can seamlessly place orders for selected products.

## Setup
Clone this repo to your desktop and run `npm install` to install all the dependencies.

To configure the application correctly, you will need to create a `.env` file and add the following data to it:
```jsx
PORT=
MONGODB_URL=

ACCESS_SECRET_KEY=
REFRESH_SECRET_KEY=

# TIME FOR TOKEN EXPIRED (MINUTES)
ACCESS_TOKEN_EXPIRESIN=
REFRESH_TOKEN_EXPIRESIN=

```

## Usage
After you clone this repo to your desktop, go to its root directory and run `npm install` to install its dependencies.

After successfully installing the required dependencies, you can launch the application by running `npm start`. This command will start the application, and you will be able to access it through the specified `PORT` that you have configured.
