{-# LANGUAGE OverloadedStrings #-}

import System.Directory (listDirectory, doesFileExist)
import System.FilePath ((</>))
import Control.Monad (forM_)
import Network.HTTP.Simple (httpLbs, parseRequest, setRequestMethod, setRequestQueryString, getResponseBody)
import qualified Data.ByteString.Lazy.Char8 as LBS

apiKey :: LBS.ByteString
apiKey = "YOUR_API_KEY"

checkFileWithVirusTotal :: FilePath -> IO ()
checkFileWithVirusTotal filePath = do
  request <- parseRequest $ "https://www.virustotal.com/vtapi/v2/file/report"
  let requestWithApiKey = setRequestQueryString [("apikey", Just apiKey)] request
  let requestWithFileHash = setRequestQueryString [("resource", Just $ LBS.pack filePath)] requestWithApiKey
  let requestWithMethod = setRequestMethod "GET" requestWithFileHash

  response <- httpLbs requestWithMethod
  let result = getResponseBody response

  putStrLn $ "Результат проверки для файла " ++ filePath ++ ": " ++ LBS.unpack result

scanDirectory :: FilePath -> IO ()
scanDirectory path = do
  contents <- listDirectory path

  forM_ contents $ \name -> do
    let fullPath = path </> name
    isFile <- doesFileExist fullPath
    if isFile
      then do
        putStrLn $ "Обнаружен файл: " ++ fullPath
        checkFileWithVirusTotal fullPath
      else putStrLn $ "Обнаружена поддиректория: " ++ fullPath

main :: IO ()
main = do
  putStrLn "Введите путь к директории для сканирования:"
  path <- getLine
  putStrLn $ "Начинаем сканирование директории: " ++ path
  scanDirectory path
