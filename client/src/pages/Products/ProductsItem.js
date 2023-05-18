import { Link } from 'react-router-dom';
const Item = ({ item }) => {
    return (
        <div class=" flex-none">
            <div>
                <Link to={`/product/${item.id}`} state={item}   ><img class="aspect-24/29" src={item.image[0]} alt="image here" /></Link>
            </div>
            <div class="text-left mt-5 ">
                <p><Link to={`/product/${item.id}`} state={item} class="font-medium hover:text-gray-500 transition ease-in-out">{item.name}</Link></p>
                <p>$ {item.price.toFixed(2)}</p>
            </div>

        </div>
    );
}

export default Item