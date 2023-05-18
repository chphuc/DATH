import { Avatar, Divider, List, Skeleton, Text, Typography } from 'antd'
import React, { useEffect, useState } from 'react'
import InfiniteScroll from 'react-infinite-scroll-component'
import { useNavigate } from 'react-router-dom'
import user from '../../assets/imgs/pasoputi on Twitter.jfif'
import PropTypes from 'prop-types'

const ListNotifications = ({ notifications, onClick }) => {
  const [ loading, setLoading ] = useState(false)
  const navigate = useNavigate()

  const loadMoreData = () => {
    if (loading) {
      return
    }
    // setLoading(true);
    // fetch('https://randomuser.me/api/?results=10&inc=name,gender,email,nat,picture&noinfo')
    //   .then((res) => res.json())
    //   .then((body) => {
    //     setData([...data, ...body.results]);
    //     setLoading(false);
    //   })
    //   .catch(() => {
    //     setLoading(false);
    //   });
  }

  const handleNotificationClick = (item) => {
    navigate(`/orders/${item.orderId}`)
    onClick()
  }

  useEffect(() => {
    loadMoreData()
  }, [])

  return (
    <div
      id="scrollableDiv"
      style={{
        height: 'fit-content',
        maxHeight: 400,
        width: 300,
        overflow: 'auto',
      }}
    >
      <InfiniteScroll
        dataLength={notifications.length}
        next={loadMoreData}
        hasMore={notifications.length < 50}
        style={{ width: '100%' }}
        // loader={
        //   <Skeleton
        //     avatar
        //     paragraph={{
        //       rows: 1,
        //     }}
        //     active
        //   />
        // }
        endMessage={<Divider plain>It is all, nothing more 🤐</Divider>}
        scrollableTarget="scrollableDiv"
      >
        <List
          className='list-notification'
          dataSource={notifications}
          renderItem={(item) => (
            <List.Item key={item.id} className='list-notification-item' onClick={() => handleNotificationClick(item)}>
              <List.Item.Meta
                avatar={<Avatar src={user} />}
                title={`${item.customer.name} has new order!`}
                description={
                  <Typography.Paragraph ellipsis={{ rows: 1 }}>
                    Please review more details to confirm this order, otherwise decline this with a reason!
                  </Typography.Paragraph>
                }
              />
            </List.Item>
          )}
        />
      </InfiniteScroll>
    </div>
  )
}

ListNotifications.propTypes = {
  notifications: PropTypes.arrayOf(PropTypes.shape({
    id: PropTypes.string.isRequired,
    orderId: PropTypes.string.isRequired,
    for: PropTypes.string.isRequired,
    type: PropTypes.string.isRequired,
    customer: PropTypes.shape({
      id: PropTypes.string.isRequired,
      name: PropTypes.string.isRequired,
    })
  })),
  onClick: PropTypes.func.isRequired,
}

export default ListNotifications