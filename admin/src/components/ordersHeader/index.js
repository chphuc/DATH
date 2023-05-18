import React from 'react'
import PropTypes from 'prop-types'
import { Layout, PageHeader } from 'antd'
import BreadCrumb from '../breadCrumb'

function OrdersHeader({ title, subtitle }) {
  return (
    <Layout className='page-header'>
      <BreadCrumb />
      <PageHeader
        className="site-page-header"
        title={title}
        // breadcrumb={{
        //   routes,
        // }}
        subTitle={subtitle}
      />
    </Layout>
  )
}

OrdersHeader.propTypes = {
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string.isRequired,
}

export default OrdersHeader
