const mongoose = require('mongoose');



const url =process.env.url
//  process.env.url
mongoose.connect(url, {
    useNewUrlParser: true, 
    useUnifiedTopology: true
}).then(() => console.log('Connected to DB')).catch((e)=> console.log('Error', e))