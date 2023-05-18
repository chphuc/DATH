import React, { useState, useEffect }from 'react'
import { Button } from 'antd'
import { EditOutlined } from '@ant-design/icons'
import AEProduct from './AEProducts'
const EditButton = (editProduct) => {
  return (
    <Button 
      onClick={() => {
        // console.log(editProduct)
      }} 
      href = {'/manage-products/Edit/' + editProduct.editProduct.id}
      type="link" icon={<EditOutlined/> } 
      size="large"
    >
    </Button>
  )
}
export default EditButton