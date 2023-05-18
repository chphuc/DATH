import HomeBanner from './HomeBanner'
import HomeCollection from './HomeCollection'
import HomeBestSeller from './HomeBestSeller'

const index = () => {
    return (
        <div>
            <HomeBanner />
            <div className="pt-32 pb-16 lg:pb-24 px-4 lg:px-12">
                <div className="mb-24">
                    <HomeCollection />
                </div>
                <HomeBestSeller />
            </div>
        </div>
    )
}

export default index