import React, { useState, useEffect } from 'react'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { Button, Form, Input, Divider, InputNumber, Modal, Card } from 'antd'
// import axios from '../../../../api'
import axios from '../../../../api'

import { useNavigate, useLocation, useParams } from 'react-router-dom'
import { ProductHeader } from '../../../../components/'
const AEProducts = () => {
  const [ form ] = Form.useForm()
  let { id } = useParams()
  const navigate = useNavigate()
  let location = useLocation()
  // console.log(location.pathname)
  let paths = location.pathname.split('/')
  console.log(paths)
  let type = paths[paths.length - 1]
  let [ editValue, setEditValue ] = useState({})

  async function fetchData() {
    let response = await axios
      .get('product/' + id)
      .catch((error) => console.log(error))

    let value = response.data
    setEditValue(value)
  }

  //
  useEffect(() => {
    if (type !== 'Add') {
      fetchData()
    }
  }, [])

  useEffect(() => {
    form.setFieldsValue({
      name: editValue.name,
      image: editValue.image,
      price: editValue.price,
      colors: editValue.colors,
      remained: editValue.remained,
      type: editValue.type,
    })
  }, [ editValue ])
  console.log(editValue)

  const success = () => {
    Modal.success({
      content: 'Successfully',
      onOk() {
        navigate(-1)
      },
    })
  }
  const onFinish = (values) => {
    if (type === 'Add') {
      axios
        .post('/product/createProduct', {
          name: values.name,
          image: values.image,
          price: values.price,
          colors: values.colors,
          remained: values.remained,
          type: values.type,
        })
        .then((res) => {
          console.log(res.data)
          success()
        })
    } else {
      axios
        .put('product/' + id, {
          name: values.name,
          image: values.image,
          price: values.price,
          colors: values.colors,
          remained: values.remained,
          type: values.type,
        })
        .then((res) => {
          console.log(res)
        })
        .catch((error) => {
          this.setState({ errorMessage: error.message })
          console.error('There was an error!', error)
        })
    }
  }

  return (
    <>
      <ProductHeader title="Manage Product" subtitle="All products" />
      <Card
        style={{
          margin: '24px',
        }}
      >
        <Button
          href="/manage-products"
          type="link"
          icon={<ArrowLeftOutlined />}
          size="small"
        >
          Manage Products
        </Button>
        <Form
          form={form}
          name="wrap"
          onFinish={onFinish}
          // wrapperCol={{ span: 16 }}
          // labelCol={{ span: 3 }}
        >
          <Divider style={{ backgroundColor: '#d8d8d8' }}>Name field</Divider>

          <Form.Item
            name="name"
            rules={[ { required: true, message: 'Please input your name!' } ]}
          >
            <Input
              // ref = {editValue}
              // className='input'
              value={editValue.name ? editValue.name : ''}
              // defaultValue = {editValue.name ? editValue.name : ''}
              // value = {'abc'}
              // defaultValue = {'abffc'}
              placeholder="Name..."
            />
          </Form.Item>
          <Divider style={{ backgroundColor: '#d8d8d8' }}>Images field</Divider>

          <Form.List
            name="image"
            rules={[ { required: true, message: 'Please input your image!' } ]}
          >
            {(fields, { add, remove }, { errors }) => (
              <>
                {fields.map((field) => (
                  <Form.Item required={false} key={field.key}>
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
                      <Input
                        // ref = {editValue}
                        // className='input'
                        name="image"
                        placeholder="Image..."
                        value={editValue.image ? editValue.image : ''}
                      />
                    </Form.Item>
                    {fields.length > 1 ? (
                      <Button
                        type="primary"
                        onClick={() => {
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
                    style={{ float: 'right', backgroundColor: ' #da3f3f' }}
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
            <InputNumber
              // ref = {editValue}
              // className='input'
              prefix="$"
              placeholder="Price..."
              value={editValue.price ? editValue.price : ''}
              style={{ width: '100%' }}
            />
          </Form.Item>

          <Divider style={{ backgroundColor: '#d8d8d8' }}>Type field</Divider>

          <Form.Item
            name="type"
            rules={[ { required: true, message: 'Please input your type!' } ]}
          >
            <Input
              // ref = {editValue}
              // className='input'
              value={editValue.type ? editValue.type : ''}
              placeholder="Type..."
            />
          </Form.Item>

          <Divider style={{ backgroundColor: '#d8d8d8' }}>Colors field</Divider>

          <Form.List
            name="colors"
            rules={[ { required: true, message: 'Please input your color!' } ]}
          >
            {(fields, { add, remove }, { errors }) => (
              <>
                {fields.map((field) => (
                  <Form.Item required={false} key={field.key}>
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
                      <Input
                        // ref = {editValue}
                        // className='input'
                        value={editValue.color ? editValue.color : ''}
                        name="color"
                        placeholder="Color..."
                      />
                    </Form.Item>
                    {fields.length > 1 ? (
                      <Button
                        type="primary"
                        onClick={() => {
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
          <Divider style={{ backgroundColor: '#d8d8d8' }}>
            Total items field
          </Divider>

          <Form.Item
            name="remained"
            rules={[
              {
                required: true,
                message: 'Please input your total items left!',
              }
            ]}
          >
            <InputNumber
              // ref = {editValue}
              // className='input'

              onClick={(e) => console.log(e.target.value)}
              placeholder="Item..."
              value={editValue.remained ? editValue.remained : ''}
              style={{ width: '100%' }}
            />
          </Form.Item>
          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              onClick={success}
              style={{ float: 'right' }}
            >
              SAVE
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </>
  )
}

export default AEProducts
