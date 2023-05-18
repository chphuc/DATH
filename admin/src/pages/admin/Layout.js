import { Layout as LayoutAntd } from 'antd'
import React, { useEffect } from 'react'
import { Outlet, useNavigate } from 'react-router-dom'
import { Header, Sider } from '../../components'
import axios from '../../api'

function Layout() {
  const navigate = useNavigate()

  useEffect(() => {
    axios.interceptors.response.use((response) => response, error => {
      if (error.response.status === 401) {
        navigate('/login')
      }
      if (error.response.data) {
        return Promise.reject(error.response.data)
      }
      return Promise.reject(error.message)
    })
  }, [])

  return (
    <LayoutAntd>
      <Header />
      <LayoutAntd className='main-content'>
        <Sider />
        <LayoutAntd>
          <LayoutAntd.Content>
            <Outlet />
          </LayoutAntd.Content>
        </LayoutAntd>
      </LayoutAntd>
    </LayoutAntd>
  )
}

export default Layout
