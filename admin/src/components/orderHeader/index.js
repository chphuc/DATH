import { Button, Descriptions, Form, Input, Layout, Modal, PageHeader, Statistic } from 'antd'
import { ReloadOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons'
import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import PropTypes from 'prop-types'
import moment from 'moment'
import './style.css'
import BreadCrumb from '../breadCrumb'
import axios from '../../api'
import { useSocket } from '../../hooks'

const { confirm } = Modal

function OrderHeader({ setRefresh, order, loading }) {
  const navigate = useNavigate()
  const [ fetching, setFetching ] = useState(false)
  const [ reason, setReason ] = useState('')
  const [ open, setOpen ] = useState(false)
  const [ form ] = Form.useForm()
  const socket = useSocket()

  const handleConfirm = () => {
    confirm({
      title: 'Are you sure to confirm this order?',
      content: 'When clicked the OK button, this order will be confirmed and it\'s status will be changed to "confirmed".',
      okText: 'Yes',
      cancelText: 'No',
      onOk() {
        setFetching(true)
        axios.post('/order/confirmOrder', { id: order.id })
          .then(response => {
            setRefresh(true)
            setFetching(false)
            socket.emit('updateOrder')
          })
          .catch(err => {
            console.log('Confirm Order Error:', err)
          })
      },
    })
  }

  const renderContent = (column = 2, size = 'small') => (
    <Descriptions size={size} column={column}>
      <Descriptions.Item label="Order ID">{order.id}</Descriptions.Item>
      <Descriptions.Item label="Customer ID">
        <Link>{order.customerId}</Link>
      </Descriptions.Item>
      <Descriptions.Item label="Creation Time">{moment(order.createdAt).format('ss:mm:hh DD-MM-YYYY')}</Descriptions.Item>
      <Descriptions.Item label="Address">{order.address}</Descriptions.Item>
    </Descriptions>
  )

  const extraContent = (
    <div
      style={{
        display: 'flex',
        width: '100%',
        justifyContent: 'flex-end',
      }}
    >
      <Statistic
        title="Status"
        value={order.status}
        style={{
          marginRight: 32,
        }}
      />
      <Statistic title="Price" prefix="$" value={order.totalAmount} />
    </div>
  )

  const Content = ({ children, extra }) => (
    <div className="content page-header-content">
      <div className="main">{children}</div>
      <div className="extra">{extra}</div>
    </div>
  )

  const handleCancel = () => {
    setReason('')
    setOpen(false)
    form.setFieldValue('reason', '')
  }

  const handleOk = () => {
    setFetching(true)
    axios.post('/order/declineOrder', { id: order.id, reason })
      .then(response => {
        setRefresh(true)
        setFetching(false)
        setOpen(false)
        socket.emit('updateOrder')
      })
      .catch(err => {
        setFetching(false)
        setOpen(false)
        console.log('Decline Order Error:', err)
      })
  }

  return (
    <Layout className='page-header'>
      <BreadCrumb />
      <PageHeader
        className="site-page-header-responsive"
        onBack={() => navigate(-1)}
        title="Order Details"
        // subTitle="This is a subtitle"
        extra={[
          <Button
            key='order-refresh'
            type="primary"
            icon={<ReloadOutlined />}
            loading={loading}
            onClick={() => setRefresh(true)}
          >Refresh</Button>,
          order.status === 'pending' && <Button
            key='order-confirm'
            type="primary"
            icon={<CheckOutlined />}
            disabled={order.status === 'confirmed'}
            onClick={handleConfirm}
            loading={fetching}
          >Confirm</Button>,
          order.status === 'pending' && <Button
            key='order-declind'
            type="primary"
            danger
            icon={<CloseOutlined />}
            disabled={order.status === 'confirmed'}
            onClick={() => setOpen(true)}
            loading={fetching}
          >Decline</Button>
        ]}
      >
        <Content extra={extraContent}>{renderContent()}</Content>
      </PageHeader>

      <Modal
        open={open}
        centered
        title='Are you sure to decline this order?'
        okText='Yes'
        okType='danger'
        cancelText='No'
        okButtonProps={{ disabled: reason === '' }}
        onCancel={handleCancel}
        onOk={handleOk}
      >
        <Form
          name="basic"
          layout='vertical'
          autoComplete="off"
          form={form}
        >
          <Form.Item
            label="Reason"
            name="reason"
            rules={[
              {
                required: true,
                message: 'Please input the reason!',
              }
            ]}
          >
            <Input.TextArea value={reason} onChange={e => setReason(e.target.value)} rows={4} required />
          </Form.Item>
        </Form>
      </Modal>

    </Layout>
  )
}

OrderHeader.propTypes = {
  setRefresh: PropTypes.func.isRequired,
  order: PropTypes.shape({
    id: PropTypes.string.isRequired,
    customerId: PropTypes.string.isRequired,
    createdAt: PropTypes.string.isRequired,
    status: PropTypes.string.isRequired,
    totalAmount: PropTypes.number.isRequired,
    adminId: PropTypes.string,
    confirmAt: PropTypes.string,
    products: PropTypes.arrayOf(PropTypes.object)
  }),
  loading: PropTypes.bool.isRequired,
}

export default OrderHeader