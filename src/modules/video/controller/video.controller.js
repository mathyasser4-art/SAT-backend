const featuredVideoModel = require('../../../../DB/models/featuredVideo.model')
const userModel = require('../../../../DB/models/user.model')

const SCOPE_PATTERN = /^(brand:[a-z0-9-]{2,40}|teacher:[0-9a-fA-F]{24})$/
const YOUTUBE_PATTERN = /^https?:\/\/(www\.|m\.)?(youtube\.com|youtu\.be)\//i
const MAX_VIDEOS = 60

// Words that identify a brand's accounts (same rule the website uses to pick the brand)
const BRAND_KEYWORDS = { mrshahin: 'shahin' }

const identityOf = (user) => `${user?.userName || ''} ${user?.email || ''} ${user?.customDomain || ''}`.toLowerCase()

// A teacher may manage their own list; a brand list belongs to that brand's
// accounts, or to teachers created by that brand's school account
const canManageScope = async (user, scope) => {
    if (!user) return false
    if (user.role === 'Admin') return true
    if (scope.startsWith('teacher:')) return scope === `teacher:${user._id}`
    const brand = scope.slice('brand:'.length)
    const keyword = BRAND_KEYWORDS[brand] || brand
    if (identityOf(user).includes(keyword)) return true
    if (user.createdBy) {
        const creator = await userModel.findById(user.createdBy).select('userName email customDomain').lean()
        return identityOf(creator).includes(keyword)
    }
    return false
}

const cleanVideo = (v, index) => ({
    id: String(v.id || `vid-${Date.now()}-${index}`).slice(0, 60),
    title: String(v.title || '').trim().slice(0, 200),
    youtubeUrl: String(v.youtubeUrl || '').trim().slice(0, 300),
    tag: String(v.tag || 'SAT Strategy').trim().slice(0, 60),
    duration: String(v.duration || 'Tutorial').trim().slice(0, 30)
})

// Public: anyone visiting the site (students included) can watch the videos
const getVideos = async (req, res) => {
    try {
        const { scope } = req.params
        if (!SCOPE_PATTERN.test(scope)) return res.status(400).json({ message: 'Invalid video list' })
        const doc = await featuredVideoModel.findOne({ scope }).lean()
        res.json({ message: 'success', saved: Boolean(doc), videos: doc ? doc.videos : [] })
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

// Teachers: replace the whole list (add, edit, delete and reorder all save this way)
const saveVideos = async (req, res) => {
    try {
        const { scope } = req.params
        if (!SCOPE_PATTERN.test(scope)) return res.status(400).json({ message: 'Invalid video list' })
        if (!(await canManageScope(req.userData, scope))) {
            return res.status(403).json({ message: 'You can only manage your own videos' })
        }
        const incoming = Array.isArray(req.body.videos) ? req.body.videos : null
        if (!incoming) return res.status(400).json({ message: 'videos must be a list' })
        if (incoming.length > MAX_VIDEOS) return res.status(400).json({ message: `At most ${MAX_VIDEOS} videos` })

        const videos = incoming.map(cleanVideo)
        if (videos.some(v => !v.title || !YOUTUBE_PATTERN.test(v.youtubeUrl))) {
            return res.status(400).json({ message: 'Each video needs a title and a YouTube link' })
        }

        const doc = await featuredVideoModel.findOneAndUpdate(
            { scope },
            { videos, updatedBy: req.userData._id },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        ).lean()
        res.json({ message: 'success', videos: doc.videos })
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

module.exports = { getVideos, saveVideos }
