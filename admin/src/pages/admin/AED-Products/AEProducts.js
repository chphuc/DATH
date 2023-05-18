import React from 'react'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { Button, Form, Input, Divider, InputNumber } from 'antd'

function AEProducts() {
  return (
    <>
      <Button 
        href="/manage-products" 
        type="link" icon={<ArrowLeftOutlined/>} 
        size="small"
      >
            Manage Products
      </Button>
      <Form
        name="wrap"
        // wrapperCol={{ span: 16 }}
        // labelCol={{ span: 3 }}

      >
        <Divider style={{ backgroundColor: '#d8d8d8' }}>Name field</Divider>

        <Form.Item
          name="name"
          rules={[ { required: true, message: 'Please input your name!' } ]}
        >
          <Input placeholder="Name..." />
        </Form.Item>
        <Divider style={{ backgroundColor: '#d8d8d8' }}>Images field</Divider>

        <Form.List
          name="image"
          rules={[ { required: true, message: 'Please input your image!' } ]}
        >
          {(fields, { add, remove }, { errors }) => (

            <>
              {fields.map((field) => (
                <Form.Item
                  required={false}
                  key={field.key}
                >
                  <Form.Item
                    {...field}
                    validateTrigger={[ 'onChange', 'onBlur' ]}
                    rules={[
                      {
                        required: true,
                        whitespace: true,
                        message: 'Please input your image.',
                      }
                    ]}
                    noStyle
                  >
                    <Input name="image" placeholder="Image..." />
                  </Form.Item>
                  {fields.length > 1 ? (
                    <Button type="primary" 
                      onClick ={() => {
                        remove(field.name)
                      }} 
                      style={{ marginTop: '20px' }}
                      danger 
                    >
                        Remove
                    </Button>

                  ) : null}
                </Form.Item>
              ))}
              <Form.Item>
                <Button
                  type="primary"
                  onClick={() => add()}
                    
                  style={{ float: 'right' }} 
                >
                    Add More Images
                </Button>
                <Form.ErrorList errors={errors} />
              </Form.Item>
            </>
          )}
        </Form.List>

        <Divider style={{ backgroundColor: '#d8d8d8' }}>Price field</Divider>

        <Form.Item
          name="price"
          rules={[ { required: true, message: 'Please input your price!' } ]}
        >
          <Input placeholder="Price..." />
        </Form.Item>

        <Divider style={{ backgroundColor: '#d8d8d8' }}>Colors field</Divider>

        <Form.List
          name="colors"
          rules={[ { required: true, message: 'Please input your color!' } ]}
        >
          {(fields, { add, remove }, { errors }) => (

            <>
              {fields.map((field) => (
                <Form.Item
                  required={false}
                  key={field.key}
                >
                  <Form.Item
                    {...field}
                    validateTrigger={[ 'onChange', 'onBlur' ]}
                    rules={[
                      {
                        required: true,
                        whitespace: true,
                        message: 'Please input your color.',
                      }
                    ]}
                    noStyle
                  >
                    <Input name="color" placeholder="Color..." />
                  </Form.Item>
                  {fields.length > 1 ? (
                    <Button type="primary" 
                      onClick ={() => {
                        remove(field.name)
                      }} 
                      style={{ marginTop: '20px' }}
                      danger 
                    >
                        Remove
                    </Button>

                  ) : null}
                </Form.Item>
              ))}
              <Form.Item>
                <Button
                  type="primary"
                  onClick={() => add()}
                    
                  style={{ float: 'right' }} 
                >
                    Add More Colors
                </Button>
                <Form.ErrorList errors={errors} />
              </Form.Item>
            </>
          )}
        </Form.List>
        <Divider style={{ backgroundColor: '#d8d8d8' }}>Total items field</Divider>
        
        <Form.Item
          name="item"
          rules={[ { required: true, message: 'Please input your total items left!' } ]}
                
        >
          <InputNumber placeholder="Item..." style={{ width:'100%' }} />
        </Form.Item>
      </Form>
    </>

  )
}

export default AEProducts