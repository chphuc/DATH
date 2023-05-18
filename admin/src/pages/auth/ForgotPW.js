import React from 'react'
import { Typography, Button, Form, Input, Card } from 'antd'
import { MailOutlined } from '@ant-design/icons'
import UI from './UI'
const { Text } = Typography
const ForgotPW = () => {
  return (
    <div className='login-container'>
      <UI />
      <div className='right-container'>
        <Card style={{ margin: '100px' }}>
          <div 
            style={{ display:'flex', 
              flexDirection: 'column', 
              alignItems: 'center',
              marginBottom: '20px' }}
          >

            <img 
              style={{ maxWidth: '50%', marginBottom: '20px', borderRadius: '10px' }}
              src='https://cpad.ask.fm/599/967/778/-159996978-1tisl61-4h3cjckc7eioagk/original/file.jpg'
            />
            <Text>Please enter your email address. </Text>
            <Text>You will receive a link to create a new password via email</Text>
          </div>

          <Form
            name="reset-password"
            className="login-form"
            initialValues={{ remember: true }}
            // onFinish={}
          >
            <Form.Item
              name="email"
              rules={[
                {
                  type: 'email',
                  message: 'The input is not valid E-mail!',
                },
                {
                  required: true,
                  message: 'Please input your E-mail!',
                }
              ]}
            >
              <Input   
                prefix={<MailOutlined className="site-form-item-icon" />} 
                placeholder="Enter email" />
            </Form.Item>
            <Form.Item>
              <Button style={{ 
                width: '100%', 
                backgroundColor: '#7DA863',
                borderRadius: '10px',
                border: '1px solid #7DA863',
                color: 'white'

              }} type="" htmlType="submit" className="forgot-form-button">
                Reset Password
              </Button>
            </Form.Item>
            <p style={{ textAlign:'center' }}>
              <a href='/login' style={{  color:'grey' }}>Cancel</a>
            </p>
    
          </Form>
        </Card>
      </div>
    </div>
  )
}

export default ForgotPW