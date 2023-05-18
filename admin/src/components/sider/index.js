import { ShoppingCartOutlined, DesktopOutlined, LineChartOutlined } from '@ant-design/icons'
import React from 'react'
import { Layout, Menu } from 'antd'
import { useNavigate } from 'react-router-dom'
import './style.css'

const items = [ 
  {
    title: 'Manage Statistic',
    icon: LineChartOutlined,
    path: '/',
    
  },
  {
    title: 'Orders',
    icon: ShoppingCartOutlined,
    path: '/orders',
    // children: [
    //   {
    //     title: 'List orders',
    //     path: '/'
    //   },
    //   {
    //     title: 'History',
    //     path: '/history'
    //   }
    // ]
  },
  {
    title: 'Manage Products',
    icon: DesktopOutlined,
    path: '/manage-products',
  }
 
]

function Sider() {
  const navigate = useNavigate()
  // const location = useLocation()
  // const paths = location.pathname.split('/')
  // console.log(location, paths)

  const keys = items.map((item) => ({
    key: item.path,
    icon: React.createElement(item.icon),
    label: item.title,
    // children: item.children?.map((child) => ({
    //   key: item.path + child.path,
    //   label: child.title,
    // }))
  }))

  const handleSiderOnclick = e => {
    navigate(e.key)
  }

  return (
    <Layout.Sider width={200} className="site-layout-background" style={{ backgroundColor: 'rgba(255, 255, 255, 0.2)', color:'black' }}>
      <Menu
        
        mode="inline"
        // defaultSelectedKeys={[ location.pathname ]}
        // defaultOpenKeys={[ '\\' + paths[1] ]}
        style={{
          height: '100%',
          borderRight: 0,
          color:'black',
          background: 'rgba(255, 255, 255, 0.2)'
        }}
        items={keys}
        onClick={handleSiderOnclick}
      />
    </Layout.Sider>
  )
}

export default Sider