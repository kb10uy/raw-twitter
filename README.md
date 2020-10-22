# raw-twitter
Twitter に生リクエストを飛ばすのに便利なやーつ

## つかいかた
1. 以下のようなテンプレートを用意する
   ```json
   {
     "endpoint": "path/to/resource.json",
     "method": "GET|POST|PUT|DELETE",
     "parameters": {
       "foo": "bar"
     }
   }
   ```
2. 環境変数に以下の項目をセットしておく。カレントディレクトリに `.env` がある場合はそれを読み込む
    * `TWITTER_CK`
    * `TWITTER_CS`
    * `TWITTER_AT`
    * `TWITTER_ATS`
3. `raw-twitter template.json`
4. レスポンスが標準出力に出てくる
