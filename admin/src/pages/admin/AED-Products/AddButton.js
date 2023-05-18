import React from 'react'
import { Button } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
function AddButton() {
  return (
    <Button 
      href="/manage-products/AEProducts" 
      type="primary" icon={<PlusOutlined/>} 
      className='add-btn' 
      size="large"
     
    >
      Add More
    </Button>
    // <Link className="ant-btn ant-btn-primary" to="/yoururl"></Link>
  )
}

export default AddButton