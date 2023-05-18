import { Space } from 'antd'
import React, { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { OrderHeader, OrdersTable } from '../../../components'
import axios from '../../../api'

const columns = [
  {
    title: 'Product ID',
    dataIndex: 'productId',
  },
  {
    title: 'Name',
    dataIndex: 'name',
  },
  {
    title: 'Type',
    dataIndex: 'type',
  },
  {
    title: 'Price',
    dataIndex: 'price',
  },
  {
    title: 'Quantity',
    dataIndex: 'quantity',
  },
  // {
  //   title: 'Total Amout',
  //   dataIndex: 'total',
  // },
]

function OrderDetail() {
  // const navigate = useNavigate()
  const { orderId } = useParams()
  const [ order, setOrder ] = useState(null)
  const [ loading, setLoading ] = useState(true)
  const [ data, setData ] = useState([])
  const [ refresh, setRefresh ] = useState(false)
  
  // const onRowClick = (record, rowIndex) => {
  //   navigate(`/pro/${record.id}`)
  // }

  useEffect(() => {
    setLoading(true)
    axios.post('/order/getOrder', { id: orderId }, { withCredentials: true })
      .then(res => {
        setData(res.data.products.map((p, index) => ({
          ...p,
          // ...getProductsData(p.id),
          key: `order-${p.id}-${index}`,
        })))
        setOrder(res.data)
        setLoading(false)
        setRefresh(false)
      })
      .catch(e => {
        console.log(e)
        setLoading(false)
        setRefresh(false)
      })
  }, [ refresh ])

  const headerProps = {
    setRefresh,
    order,
    loading
  }

  const props = {
    columns,
    loading,
    data,
    hasHeader: false,
  }

  return (
    <>
      {order && (
        <>
          <OrderHeader {...headerProps} />
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
      )}
    </>
  )
}

export default OrderDetail