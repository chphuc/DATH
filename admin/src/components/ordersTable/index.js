import PropTypes from 'prop-types'
import { Button, Card, Col, Form, Input, Radio, Row, Space, Table, Typography } from 'antd'
import { ReloadOutlined, ColumnHeightOutlined, SettingOutlined } from '@ant-design/icons'
import './style.css'
import { useState } from 'react'

const filterOptions = [
  {
    label: 'All',
    value: 'all',
    func: i => i
  },
  {
    label: 'Pending',
    value: 'pending',
    func: i => i.status === 'pending'
  },
  {
    label: 'Confirmed',
    value: 'confirmed',
    func: i => i.status === 'confirmed'
  }
]

function OrdersTable({ columns, data, loading, hasHeader, onSearch, onRowClick = () => {} }) {
  const [ form ] = Form.useForm()
  const [ searching, setSearching ] = useState(false)
  const [ filter, setFilter ] = useState(filterOptions[0])
  
  const onFinish = (values) => {
    // console.log(values)
    // setSearching(true)
    onSearch(values)
  }

  const onReset = () => {
    form.resetFields()
  }

  const onChangeFilter = ({ target: { value } }) => {
    var filter = filterOptions.find(i => i.value === value)
    filter ? setFilter(filter) : setFilter(filterOptions[0])
  }

  return (
    <>
      {
        hasHeader && 
      <Card style={{
        marginBottom: '18px'
      }}>
        <Form 
          layout='inline'
          form={form}
          onFinish={onFinish}
        >
          <Col span={6}>
            <Form.Item label="Status">
              <Radio.Group
                options={filterOptions}
                value={filter.value}
                optionType='button'
                onChange={onChangeFilter}
              ></Radio.Group>

            </Form.Item>

          </Col>
          <Col span={6}>
            <Form.Item label='Order ID' name="orderId">
              <Input placeholder='Please enter' />
            </Form.Item>

          </Col>
          <Col span={6}>
            <Form.Item label='Customer ID' name="customerId">
              <Input placeholder='Please enter' />
            </Form.Item>

          </Col>

          <Col span={6} style={{
            textAlign: 'right'
          }}>
            <Form.Item
              style={{
                marginRight: '0'
              }}
            >
              <Button
                type="primary"
                htmlType="submit"
                style={{
                  margin: '0 8px'
                }}
                loading={searching}
              >
                Search
              </Button>
              <Button htmlType="button" onClick={onReset}>
                Reset
              </Button>

            </Form.Item>
          </Col>
        </Form>
      </Card>
      }

      <Card>
        <Row justify='space-between'>
          <Col><Typography.Title level={4} style={{
            marginBottom: '32px'
          }}>Table</Typography.Title></Col>
          <Col>
            <Space>

              <Button type='text' className='button-hover-color'>
                <ReloadOutlined />
              </Button>
              <Button type='text' className='button-hover-color'>
                <ColumnHeightOutlined />
              </Button>
              <Button type='text' className='button-hover-color'>
                <SettingOutlined />
              </Button>
            </Space>
          </Col>
        </Row>
        <Table
          bordered
          loading={loading}
          columns={columns}
          dataSource={data.filter(filter.func)}
          onRow={(record, rowIndex) => {
            return {
              onClick: event => onRowClick(record, rowIndex), // click row
            // onDoubleClick: event => {}, // double click row
            // onContextMenu: event => {}, // right button click row
            // onMouseEnter: event => {}, // mouse enter row
            // onMouseLeave: event => {}, // mouse leave row
            }
          }}
        />
      </Card>
    </>
  )
}

OrdersTable.propTypes = {
  columns: PropTypes.arrayOf(PropTypes.shape({
    title: PropTypes.string,
    dataIndex: PropTypes.string,
  })).isRequired,
  data: PropTypes.arrayOf(PropTypes.object),
  loading: PropTypes.bool,
  onRowClick: PropTypes.func
}

OrdersTable.defaultProp = {
  data: [],
  loading: false,
}

export default OrdersTable