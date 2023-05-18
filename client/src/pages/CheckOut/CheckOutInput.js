import React from 'react'

const CheckOutInput = ({ name, onChange, value, placeholder, disabled = false }) => {
    return (
        <div>
            <input
                type="text"
                className="font-medium p-2 border border-gray-300 text-sm rounded focus:ring-blue-500 focus:border-blue-500 block w-full disabled:bg-neutral-100 disabled:text-gray-400"
                placeholder={placeholder}
                name={name}
                onChange={onChange}
                required
                disabled={disabled}
                value={value}
            />
        </div>
    )
}

export default CheckOutInput