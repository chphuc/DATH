import { Card, Statistic, Table, Col, Row } from 'antd'
import './month.scss'
import React, { useEffect, useState } from 'react'
import { SttHeader } from '../../../components/'
import { ShoppingCartOutlined, PoundOutlined } from '@ant-design/icons'
const { Column } = Table
import axios from '../../../api'
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
)
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js'

import { Bar } from 'react-chartjs-2'
function Statisticmonth() {
  const [ revenue1, setRevenue1 ] = useState(0)
  const [ revenue2, setRevenue2 ] = useState(0)
  const [ revenue3, setRevenue3 ] = useState(0)
  const [ revenue4, setRevenue4 ] = useState(0)
  const [ revenue5, setRevenue5 ] = useState(0)
  const [ revenue6, setRevenue6 ] = useState(0)
  const [ revenue7, setRevenue7 ] = useState(0)
  const [ revenue8, setRevenue8 ] = useState(0)
  const [ revenue9, setRevenue9 ] = useState(0)
  const [ revenue10, setRevenue10 ] = useState(0)
  const [ revenue11, setRevenue11 ] = useState(0)
  const [ revenue12, setRevenue12 ] = useState(0)
  const [ revenueMonth, setRevenueMonth ] = useState(0)
  const [ orderMonth, setOrderMonth ] = useState(0)
  const [ revenueToday, setRevenueToday ] = useState(0)
  const [ orderToday, setOrderToday ] = useState(0)
  const [ orderTshirt, setOrderTshirt ] = useState(0)
  const [ orderJacket, setOrderJacket ] = useState(0)
  const [ orderPants, setOrderPants ] = useState(0)
  const [ orderSandals, setOrderSandals ] = useState(0)
  const [ orderHat, setOrderHat ] = useState(0)
  const [ orderDress, setOrderDress ] = useState(0)
  const [ orderBag, setOrderBag ] = useState(0)
  const [ orderBelt, setOrderBelt ] = useState(0)

  var datenow = new Date().getDate()

  var monthnow = new Date().getMonth() + 1

  var yearnow = new Date().getFullYear()

  let today =
    yearnow.toString() + '-' + monthnow.toString() + '-' + datenow.toString()
  useEffect(() => {
    let revenuemonth = 0
    let ordermonth = 0
    let revenuetoday = 0
    let ordertoday = 0
    let ordershirt = 0
    let orderjacket = 0
    let orderpants = 0
    let orderhats = 0
    let ordersandals = 0
    let orderdresses = 0
    let orderbelt = 0
    let orderbags = 0
    let Jan = 0
    let Fer = 0
    let March = 0
    let April = 0
    let May = 0
    let June = 0
    let July = 0
    let August = 0
    let September = 0
    let October = 0
    let November = 0
    let December = 0
    axios
      .get('/statistic/getOrderToday')

      .then((res) => {
        console.log(res.data)
        res.data.map((co) => {
          if(co.status === 'confirmed') {
            co.products.map((m) => {
              
              axios.get('/statistic/getProductId').then((products) => {
                products.data.map((product) => {
                  // console.log(product.id, m.id)
                  if (product.id === m.productId) {
                    if (product.type.toString() === 'shirts') {
                      ordershirt = ordershirt + m.quantity
                      setOrderTshirt(ordershirt)
                    }
                    if (product.type.toString() === 'jacket') {
                      orderjacket = orderjacket + m.quantity
                      setOrderJacket(orderjacket)
                    }
                    if (product.type.toString() === 'pants') {
                      orderpants = orderpants + m.quantity
                      setOrderPants(orderpants)
                    }
                    if (product.type.toString() === 'hats') {
                      orderhats = orderhats + m.quantity
                      setOrderHat(orderhats)
                    }
                    if (product.type.toString() === 'dresses') {
                      orderdresses = orderdresses + m.quantity
                      setOrderDress(orderdresses)
                    }
                    if (product.type.toString() === 'bags') {
                      orderbags = orderbags + m.quantity
                      setOrderBag(orderbags)
                    }
                    if (product.type.toString() === 'belts') {
                      orderbelt = orderbelt + m.quantity
                      setOrderBelt(orderbelt)
                    }
                    if (product.type.toString() === 'sandals') {
                      ordersandals = ordersandals + m.quantity
                      setOrderSandals(ordersandals)
                    }
                  }
                })
              })
              
            })

            if (co.createdAt.search(today.toString()) !== -1) {
              revenuetoday = revenuetoday + co.totalAmount
              ordertoday = ordertoday + 1

              setRevenueToday(revenuetoday)
              setOrderToday(ordertoday)
            }
            let Month = co.createdAt.slice(5, 7)
            if (Month.toString() === monthnow.toString()) {
              revenuemonth = revenuemonth + co.totalAmount
              ordermonth = ordermonth + 1
              setRevenueMonth(revenuemonth)
              setOrderMonth(ordermonth)
            }

            if (Month.toString() === '1') {
              Jan = Jan + co.totalAmount
              setRevenue1(Jan)
            }
            if (Month.toString() === '2') {
              Fer = Fer + co.totalAmount
              setRevenue2(Fer)
            }
            if (Month.toString() === '3') {
              March = March + co.totalAmount
              setRevenue3(March)
            }
            if (Month.toString() === '4') {
              April = April + co.totalAmount
              setRevenue4(April)
            }
            if (Month.toString() === '5') {
              May = May + co.totalAmount
              setRevenue5(May)
            }
            if (Month.toString() === '6') {
              June = June + co.totalAmount
              setRevenue6(June)
            }
            if (Month.toString() === '7') {
              July = July + co.totalAmount
              setRevenue7(July)
            }
            if (Month.toString() === '8') {
              August = August + co.totalAmount
              setRevenue8(August)
            }
            if (Month.toString() === '9') {
              September = September + co.totalAmount
              setRevenue9(September)
            }
            if (Month.toString() === '10') {
              October = October + co.totalAmount
              setRevenue10(October)
            }
            if (Month.toString() === '11') {
              November = November + co.totalAmount
              setRevenue11(November)
            }
            if (Month.toString() === '12') {
              December = December + co.totalAmount
              setRevenue12(December)
            }
          }
        })
      })
  }, [])

  const options = {
    responsive: true,
    interaction: {
      mode: 'index',
      intersect: false,
    },
    stacked: false,
    plugins: {
      title: {
        display: true,
        text: 'Revenue of Month',
      },
    },
    scales: {
      y: {
        type: 'linear',
        display: true,
        position: 'left',
      },
    },
  }

  const labels = [
    'January',
    'February',
    'March',
    'April',
    'May',
    'June',
    'July',
    'August',
    'September',
    'October',
    'November',
    'December'
  ]

  const dataChart = {
    key: 'chart',
    labels,
    datasets: [
      {
        label: 'Revenue',
        data: [
          revenue1,
          revenue2,
          revenue3,
          revenue4,
          revenue5,
          revenue6,
          revenue7,
          revenue8,
          revenue9,
          revenue10,
          revenue11,
          revenue12
        ],
        borderColor: 'rgb(255, 99, 132)',
        backgroundColor: '#367e62',
        yAxisID: 'y',
      }
    ],
  }
  const dataitems1 = [
    {
      time: 'Shirt',
      revenue: orderTshirt,
      key: 'shirt',
    },
    {
      time: 'Jacket',
      revenue: orderJacket,
      key: 'jacket',
    },
    {
      time: 'Pants',
      revenue: orderPants,
      key: 'pants',
    },
    {
      time: 'Hats',
      revenue: orderHat,
      key: 'hats',
    }
  ]
  const dataitems2 = [
    {
      time: 'Sandals',
      revenue: orderSandals,
      key: 'sandals',
    },
    {
      time: 'Bags',
      revenue: orderBag,
      key: 'bags',
    },
    {
      time: 'Belts',
      revenue: orderBelt,
      key: 'belts',
    },
    {
      time: 'Dresses',
      revenue: orderDress,
      key: 'dress',
    }
  ]
  return (
    <>
      <SttHeader
        title="Manage Revenue "
        // subtitle=''
      />

      <div className="container">
        <div className="site-statistic-demo-card">
          <Row gutter={20}>
            <Col className="today">
              <Card>
                <Statistic
                  title="Order today"
                  key="ordertoday"
                  value={orderToday}
                  valueStyle={{
                    color: '#367e62',
                  }}
                  suffix={<ShoppingCartOutlined />}
                />
              </Card>
            </Col>
            <Col className="today">
              <Card>
                <Statistic
                  key="revenuetoday"
                  title="Revenue today"
                  value={revenueToday}
                  precision={2}
                  valueStyle={{
                    color: '#cf1322',
                  }}
                  suffix={<PoundOutlined />}
                />
              </Card>
            </Col>

            <Col className="today">
              <Card>
                <Statistic
                  key="ordermonth"
                  title="Order this month"
                  value={orderMonth}
                  valueStyle={{
                    color: '#367e62',
                  }}
                  suffix={<ShoppingCartOutlined />}
                />
              </Card>
            </Col>
            <Col className="today">
              <Card>
                <Statistic
                  key="revenuemonth"
                  title="Revenue this month"
                  value={revenueMonth}
                  precision={2}
                  valueStyle={{
                    color: '#cf1322',
                  }}
                  suffix={<PoundOutlined />}
                />
              </Card>
            </Col>
          </Row>
        </div>
        <div className="chart">
          <div className="chartheader">Chart Revenue</div>
          <div className="chartbody">
            <Bar options={options} data={dataChart} />
          </div>
        </div>
        <div className="items">
          <div className="itemleft">
            <div className="itemsHeader">Statistic order by items</div>
            <Table bordered dataSource={dataitems1} key={dataitems1}>
              <Column
                title="Name of item"
                dataIndex="time"
                key="time"
                style={{ backgroundColor: '#ee5d0b' }}
              />
              <Column title="Num of order" dataIndex="revenue" key="revenue" />
            </Table>
          </div>
          <div className="itemright">
            <div className="itemsHeader">Statistic order by items</div>
            <Table bordered dataSource={dataitems2} key={dataitems2}>
              <Column
                title="Name of item"
                dataIndex="time"
                key="time"
                style={{ backgroundColor: '#ee5d0b' }}
              />
              <Column title="Num of order" dataIndex="revenue" key="revenue" />
            </Table>
          </div>
        </div>
      </div>
    </>
  )
}
export default Statisticmonth
