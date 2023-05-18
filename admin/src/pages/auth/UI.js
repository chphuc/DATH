import React from 'react'
import { Carousel } from 'antd'
import './auth.scss'
function UI() {
  return (
    <Carousel
      dots={false}
      draggable
      autoplay>
      <div>
        <img className='img-carousel' src= 'https://www.simplilearn.com/ice9/free_resources_article_thumb/how_to_become_A_programmer.jpg'></img>
      </div>
      <div>
        <img className='img-carousel' src='https://www.turing.com/blog/wp-content/uploads/2022/02/great-programmer.jpg'></img>
      </div>

    </Carousel>

  )
}

export default UI
