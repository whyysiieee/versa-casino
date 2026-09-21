// Точка входа для Vercel Serverless Functions.
// Vercel находит все файлы в папке /api и превращает каждый в отдельную функцию.
// Мы просто переиспользуем готовое Express-приложение из server.js,
// а vercel.json перенаправляет ВСЕ запросы (включая статику из public/) сюда.
module.exports = require('../server.js');
