import React, { useState, useEffect, useRef } from 'react'
import { Table, Tag, Space, Modal, Input, Button, Card, Typography, Select } from 'antd'
import axios from '../../../api'
import { DeleteOutlined, SearchOutlined } from '@ant-design/icons'
import EditButton from './AED-Products/EditButton'
import './ManageProducts.scss'
import { ProductHeader } from '../../../components/'
import AddButton  from './AED-Products/AddButton'

const items = [ 'all', 'shirts', 'pants', 'bags', 'glasses', 'shoes', 'sandals' ]
function ManageProducts() {
  const [ rootData, setRootData ] = useState([])
  const [ dataSource, setDataSource ] = useState([])
  const [ filteredInfo, setFilteredInfo ] = useState({})
  const [ sortedInfo, setSortedInfo ] = useState({})
  const [ filteredName, setFilteredName ] = useState('')
  const [ inputValue, setInputValue ] = useState('')
  const [ valueTypeCurrent, setValueTypeCurrent ] = useState('all')
  // const [ countSelect, setCountSelect ] = useState(1)
  // const count = useRef(0)
  // const [ editingProduct, setEditingProduct] = useState(null)
  const fetchData = async () => {
    await axios.get('/product/getAllProduct')
      .then(res => {
        setDataSource(res.data.map((item, index) => ({
          ...item,
          key: item.id,
          index,
        })))
        setRootData(res.data.map((item, index) => ({
          ...item,
          key: item.id,
          index,
        })))
        // console.log(res.data, "fdsfs: ", dataSource)
      })
      .catch(error => console.log(error))
  }
  useEffect(() => {
    fetchData()
  }, [])
  
  useEffect(() => {
    if (valueTypeCurrent === 'all') {
      fetchData()
      return
    }
    const newData = rootData.filter(item => item.type === valueTypeCurrent)
    setDataSource(newData)
  }, [ valueTypeCurrent ])
  
  const handleChange = (pagination, filters, sorter) => {
    console.log('Various parameters', pagination, filters, sorter)
    setFilteredName(filters.name[0])
    setFilteredInfo(filters)
    setSortedInfo(sorter)
  }

  const clearAll = () => {
    setFilteredInfo({})
    setFilteredName('')
    setSortedInfo({})
    setInputValue('')
    setValueTypeCurrent('all')
    // console.log(valueTypeCurrent)
  }

  const onDeleteStudent = record => {
    Modal.confirm({
      title: 'Are you sure,you want to delete this product?',
      onOk: () => {
        axios.delete('product/' + record.id)
          .then(
            setDataSource(pre => {
              console.log(pre, record)
              return pre.filter(student => student.id !== record.id)
            })
          )
      }
    })
  }

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name', 
      align: 'center',
      filteredValue: (filteredInfo.name || [ filteredName ]) || null,
      filterDropdown: ({ setSelectedKeys, selectedKeys, confirm }) => {
        return (
          <Input.Search placeholder='Type text here'
            className="search-name"
            value={selectedKeys[0]}
            onChange={(e) => {
              setSelectedKeys(e.target.value ? [ e.target.value ] : [])
              setFilteredName(e.target.value ? e.target.value : '')
            }}
            // onChange={() => {
            //   // console.log(selectedKeys)
            //   // confirm()setFilteredName(e.target.value)
            //   setFilteredName(e.target.value)
            // }}
            onSearch={() => {
              confirm()
            }}
          /> 

        )

      },
      filterIcon:() => {
        return <SearchOutlined/>
      },
      onFilter:(value, record) => {
        return record.name.toLowerCase().includes(value.toLowerCase())
      }
    },
    {
      title: 'Image',
      dataIndex: 'image',
      key: 'image',
      align: 'center',  
      width:400,
      render: (images) => (
        images.map((image, idx) => {
          return (
            <img 
              key={idx}
              src={image} 
              alt=""
              style={{ width: '80px', marginTop:'10px' }} 
            /> 
          )
        })
      ),
      
    },
    {
      title: 'Price ($)',
      dataIndex: 'price',
      key: 'price',
      align: 'center',
      sortOrder: sortedInfo.columnKey === 'price' ? sortedInfo.order : null,
      sorter: (a, b) => {        
        return a.price - b.price
      }
    },
    {
      title: 'Remained',
      dataIndex: 'remained',
      key: 'remained',
      align: 'center',
      sortOrder: sortedInfo.columnKey === 'remained' ? sortedInfo.order : null,
      sorter: (a, b) => a.remained - b.remained,
    },
    {
      title: 'Colors',
      key: 'color',
      dataIndex: 'color',
      align: 'center',
      render: (_, { colors }) => (
        <>
          {
            colors.map((color) => {
              return (
                <Tag color={color} key={color}
                  style={{ marginTop:'10px' }} >
                  <Space size="middle">
                    {color.toUpperCase()}
                  </Space>
                </Tag>
              )
            })}
        </>
      ),
    },
    {
      title: 'Action',
      key: 'action',
      align: 'center',
      render: (record) => (
        
        <Space size="middle" style = {{ }}>
          <EditButton 
            editProduct = {record}
          />
          <DeleteOutlined 
            style={{ fontSize: '18px', color: 'red' }}
            onClick={() => {
              onDeleteStudent(record)
            }} 
          />
        </Space>
      ),
    }
  ]

  return (
    <>
      <ProductHeader 
        title='Manage Product' 
        subtitle='All products'

      />
      <Card style={{
        margin: '24px 24px 0 24px',
      }}>
        <Space
          style={{
            display: 'flex',
            justifyContent: 'space-between'
          }}>
          <Space>
            <Select 
              showSearch
              // placeholder="Select a type"
              defaultValue="all"
              style={{ width: 130 }} 
              onChange={(value) => setValueTypeCurrent(value)}
              value = {valueTypeCurrent}
            >
              {
                items.map((item, index) => {
                  return <Select.Option key={index} value={item}></Select.Option>
                })
              }
            </Select>
          </Space>
          <Input.Search
            className="search-name"
            placeholder="Search here..."
            value = {inputValue}  
            onChange={(e) => {
              // console.log(e)
              setFilteredName(e.target.value)
              setInputValue(e.target.value)
              // console.log(filteredName)
            }}
            onSearch={(value) => {
              setInputValue(value)
              setFilteredName(value)
            }}
          />
          <Space>
            <Button 
              className='reset-btn' 
              onClick={clearAll}
            >
              Reset filters
            </Button>
            <AddButton/>
          </Space>  
        </Space>

      </Card>

      <Space
        style= {{           
          padding: '24px' }}
      >
        <Card>
          <Space
            style= {{           
            }}
          >
            <Typography.Title level={4}>
              Table
            </Typography.Title>

          </Space>

          <Table 
            bordered
            className="product-table"
            columns={columns} 
            dataSource={dataSource} 
            rowClassName={(record, index) => index % 2 === 0 ? 'table-row-light' :  'table-row-dark'}
            pagination={{ pageSize: 10 }}
            scroll={{ y: 450 }}  
            onChange={handleChange}
          />
        </Card>
      </Space>
    </>

  )
}

export default ManageProducts