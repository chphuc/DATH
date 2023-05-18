import Tippy from '@tippyjs/react/headless';

import { BsChevronDown } from 'react-icons/bs'

const NavBarItem = ({ title, fullWidth, moreInfomation, children }) => {
    return (
        <div>
            <Tippy
                interactive
                placement="bottom-start"
                render={attrs => (
                    <div className="box" tabIndex="-1" {...attrs}>
                        {
                            !fullWidth ?
                                <>
                                    <div className="shadow-md p-4 bg-white">
                                        {children?.map(item => (
                                            <div key={item.title} className="min-w-250 py-2 px-3 cursor-pointer text-gray-400 hover:bg-gray-100 hover:text-black">
                                                {item.title}
                                            </div>
                                        ))}
                                    </div>
                                </>
                                :
                                <>
                                    <div className="relative -left-2 w-screen shadow-md bg-white px-16 pt-5 pb-12">
                                        <div className={"w-full " + (moreInfomation ? 'flex' : '')}>
                                            <div className={"flex " + (moreInfomation ? 'w-2/3' : '')}>
                                                {children?.map((col, index) => (
                                                    <div key={index} className="w-1/2">
                                                        {col.children?.map(row => (
                                                            <div key={row.title} className="flex py-2 px-3 cursor-pointer text-gray-400 hover:bg-gray-100 hover:text-black">
                                                                <p>{row.title}</p>
                                                                {row.description && row.description == 'hot' && <span className="relative left-2 bottom-2 px-2 bg-orange-500 text-white text-sm rounded-lg">{row.description}</span>}
                                                                {row.description && row.description == 'new' && <span className="relative left-2 bottom-2 px-2 bg-purple-500 text-white text-sm rounded-lg">{row.description}</span>}
                                                            </div>
                                                        ))}
                                                    </div>
                                                ))}
                                            </div>
                                            {moreInfomation ?
                                                <div className={" " + (moreInfomation ? 'w-1/3' : '')}>
                                                    {moreInfomation}
                                                </div>
                                                :
                                                <></>
                                            }
                                        </div>
                                    </div>
                                </>
                        }
                    </div>
                )}
            >
                <div className="flex items-center cursor-pointer">
                    <p className="font-medium">{title || "Default Content"}</p>
                    <div className="px-2">
                        <BsChevronDown className="w-2" />
                    </div>
                </div>
            </Tippy>
        </div>
    )
}

export default NavBarItem