import { Breadcrumb } from 'antd'
import { HomeOutlined } from '@ant-design/icons'
import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { capitalizeFirstLetter } from '../../Helpers'

function BreadCrumb() {
  const location = useLocation()
  let pos = location.pathname.indexOf('Edit/')
  // = location.pathname.split('/').filter((i) => i)
  let pathSnippets
  if(pos !== -1) {
    let str1 = location.pathname.slice(0, pos + 4)
    pathSnippets = str1.split('/').filter((i) => i)
    // console.log(pathSnippets)
  } else{
    pathSnippets = location.pathname.split('/').filter((i) => i)
  }
  // console.log(pathSnippets)
  const extraBreadcrumbItems = pathSnippets.map((name, index) => {
    const url = `/${pathSnippets.slice(0, index + 1).join('/')}`
    return (
      <Breadcrumb.Item key={url}>
        <Link to={url}>{capitalizeFirstLetter(name)}</Link>
      </Breadcrumb.Item>
    )
  })
  const breadcrumbItems = [
    <Breadcrumb.Item key="home">
      <Link to="/">
        <HomeOutlined />
      </Link>
    </Breadcrumb.Item>
  ].concat(extraBreadcrumbItems)
  return (
    <Breadcrumb
      style={{
        margin: '16px 0',
      }}
    >
      {breadcrumbItems}
    </Breadcrumb>
  )
}

export default BreadCrumb
