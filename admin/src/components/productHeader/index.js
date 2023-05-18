import React from 'react'
import PropTypes from 'prop-types'
import { Layout, PageHeader } from 'antd'
import BreadCrumb from '../breadCrumb'
import { useLocation } from 'react-router-dom'

const ProductHeader = ({ title, subtitle }) => {
  const location = useLocation()  
  const contain = location.pathname.includes('Add' || 'Edit')
  // console.log(contain)
  return (
    <Layout className='page-header'>
      <BreadCrumb />
      <PageHeader
        className="site-page-header"
        title={title}

        subTitle={contain ? '' : subtitle }
      />
    </Layout>
  )
}

ProductHeader.propTypes = {
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string.isRequired,
}
export default ProductHeader