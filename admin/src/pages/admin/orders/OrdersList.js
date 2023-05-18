import { useEffect, useState } from 'react'
import moment from 'moment'
import { OrdersHeader, OrdersTable } from '../../../components'
import { Space } from 'antd'
import { useNavigate } from 'react-router-dom'
import axios from '../../../api'
import { useSocket } from '../../../hooks'

const columns = [
  {
    title: 'ID',
    dataIndex: 'id',
  },
  {
    title: 'Customer ID',
    dataIndex: 'customerId',
  },
  {
    title: 'Created At',
    dataIndex: 'createdAt',
  },
  {
    title: 'Confirmed At',
    dataIndex: 'confirmAt',
  },
  {
    title: 'Admin Confirmed ID',
    dataIndex: 'confirmByAdminId',
  },
  {
    title: 'Amount',
    dataIndex: 'totalAmount',
  },
  {
    title: 'Status',
    dataIndex: 'status',
  }
]

function OrdersList() {
  const navigate = useNavigate()
  const [ loading, setLoading ] = useState(true)
  const [ data, setData ] = useState([])
  const [ search, setSearch ] = useState({ orderId: '', customerId: '' })
  const socket = useSocket()
  
  const onRowClick = (record, rowIndex) => {
    navigate(`/orders/${record.id}`)
  }

  const onSearch = (value) => {
    if (!value.orderId) {
      value.orderId = ''
    }
    if (!value.customerId) {
      value.customerId = ''
    }
    setSearch({
      orderId: value.orderId,
      customerId: value.customerId,
    })
  }

  const getOrders = () => {
    return axios.get('/order/getAllOrders', { withCredentials: true })
      // .then(res => res.json())
      .then(res => {
        setData(res.data.map((item, index) => ({
          ...item,
          key: item.id,
          index,
          createdAt: !item.createdAt ? '' : moment(item.createdAt).format('hh:mm:ss DD-MM-YYYY'),
          confirmAt: !item.confirmAt ? '' : moment(item.updatedAt).format('hh:mm:ss DD-MM-YYYY'),
        })))
        setLoading(false)
      })
      .catch(e => {
        // alert('get data failed!')
        console.log(e)
        setLoading(false)
      })
  }

  useEffect(() => {
    // setLoading(true)
    getOrders()
  }, [])

  useEffect(() => {
    if (socket) {
      socket.on('newOrder', () => {
        getOrders()
      })

      socket.on('updateOrder', () => {
        getOrders()
      })
  
      return () => {
        socket.off('updateOrder')
      }
    }
  }, [ socket ])

  const props = {
    columns,
    loading,
    data: data.filter(order => order.id.includes(search.orderId) && order.customerId.includes(search.customerId)),
    hasHeader: true,
    onRowClick,
    onSearch
  }

  return (
    <>
      <OrdersHeader title='Orders' subtitle='All orders' />
      <Space
        direction="vertical"
        size="middle"
        style={{
          display: 'flex',
          padding: '24px'
        }}
      >
        <OrdersTable {...props} />

      </Space>
    </>
  )
}

export default OrdersList