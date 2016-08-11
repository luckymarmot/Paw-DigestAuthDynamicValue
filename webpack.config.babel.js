import webpack from 'webpack'
import path from 'path'

const name = 'DigestAuthDynamicValue'

const production = process.env.NODE_ENV === 'production'

const config = {
  target: 'web',
  entry: [
    'immutable',
    './src/DigestAuthDynamicValue.js'
  ],
  output:{
    path: path.join(__dirname,
      './build/com.luckymarmot.PawExtensions.DigestAuthDynamicValue'),
    pathInfo: true,
    publicPath: '/build/',
    filename: name+'.js'
  },
  module: {
    loaders: [
      {
        loader: 'babel-loader',
        include: [
          path.resolve(__dirname, 'src'),
        ],
        test: /\.jsx?$/,
      }
    ]
  }
}
module.exports = config
