#!/usr/bin/env node

/**
 * Script de vérification de la configuration de sécurité
 * Exécutez : node check-security.js
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 Vérification de la configuration de sécurité...\n');

let errors = 0;
let warnings = 0;

// Vérifier que .env existe
function checkEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) {
    console.error('❌ ERREUR : Fichier .env manquant !');
    console.error('   Solution : Copiez .env.example vers .env');
    errors++;
    return false;
  }
  console.log('✅ Fichier .env trouvé');
  return true;
}

// Vérifier les variables d'environnement
function checkEnvVariables() {
  require('dotenv').config();
  
  const requiredVars = [
    'STAFF_PASSWORD',
    'FIVEM_SECRET',
    'JWT_SECRET',
    'SESSION_SECRET'
  ];

  const weakPasswords = ['admin', 'password', '123456', '2025', 'test', 'demo'];

  for (const varName of requiredVars) {
    const value = process.env[varName];
    
    if (!value) {
      console.error(`❌ ERREUR : ${varName} n'est pas défini dans .env`);
      errors++;
      continue;
    }

    // Vérifier la longueur
    if (value.length < 16) {
      console.warn(`⚠️  ${varName} est trop court (minimum 16 caractères)`);
      warnings++;
    }

    // Vérifier les mots de passe faibles
    if (weakPasswords.some(weak => value.toLowerCase().includes(weak))) {
      console.error(`❌ ERREUR : ${varName} utilise un mot de passe faible !`);
      errors++;
    } else {
      console.log(`✅ ${varName} configuré`);
    }
  }
}

// Vérifier que .gitignore protège .env
function checkGitignore() {
  const gitignorePath = path.join(__dirname, '.gitignore');
  if (!fs.existsSync(gitignorePath)) {
    console.warn('⚠️  ATTENTION : .gitignore manquant');
    warnings++;
    return;
  }

  const content = fs.readFileSync(gitignorePath, 'utf8');
  if (!content.includes('.env')) {
    console.error('❌ ERREUR : .env n\'est pas dans .gitignore !');
    errors++;
  } else {
    console.log('✅ .env est protégé par .gitignore');
  }
}

// Vérifier que l'ancien fichier de config n'existe plus
function checkOldConfigFile() {
  const oldConfigPath = path.join(__dirname, 'api', 'staff_config.json');
  if (fs.existsSync(oldConfigPath)) {
    console.error('❌ ERREUR : api/staff_config.json existe encore !');
    console.error('   Ce fichier contient des mots de passe en clair.');
    console.error('   Solution : Supprimez-le avec : Remove-Item api\\staff_config.json');
    errors++;
  } else {
    console.log('✅ Ancien fichier de config supprimé');
  }
}

// Vérifier les dépendances de sécurité
function checkDependencies() {
  const packageJsonPath = path.join(__dirname, 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  
  const securityDeps = ['helmet', 'express-rate-limit', 'express-validator', 'cors'];
  
  for (const dep of securityDeps) {
    if (packageJson.dependencies[dep]) {
      console.log(`✅ ${dep} installé`);
    } else {
      console.error(`❌ ERREUR : ${dep} manquant !`);
      console.error('   Solution : npm install');
      errors++;
    }
  }
}

// Vérifier que les dépendances sont installées
function checkNodeModules() {
  const nodeModulesPath = path.join(__dirname, 'node_modules');
  if (!fs.existsSync(nodeModulesPath)) {
    console.error('❌ ERREUR : node_modules manquant !');
    console.error('   Solution : npm install');
    errors++;
  } else {
    console.log('✅ node_modules installé');
  }
}

// Exécuter toutes les vérifications
function runChecks() {
  console.log('═══════════════════════════════════════════════════\n');
  
  console.log('📁 Vérification des fichiers...');
  checkEnvFile() && checkEnvVariables();
  checkGitignore();
  checkOldConfigFile();
  
  console.log('\n📦 Vérification des dépendances...');
  checkNodeModules();
  checkDependencies();
  
  console.log('\n═══════════════════════════════════════════════════');
  console.log('\n📊 RÉSUMÉ :');
  
  if (errors === 0 && warnings === 0) {
    console.log('✅ Aucun problème détecté !');
    console.log('🎉 Votre configuration est SÉCURISÉE.');
    console.log('\n💡 Vous pouvez démarrer le serveur avec : npm start');
    process.exit(0);
  } else {
    if (errors > 0) {
      console.error(`\n❌ ${errors} erreur(s) trouvée(s) !`);
      console.error('⚠️  CORRIGEZ LES ERREURS AVANT DE DÉMARRER LE SERVEUR');
    }
    if (warnings > 0) {
      console.warn(`\n⚠️  ${warnings} avertissement(s)`);
    }
    
    console.log('\n📚 Consultez INSTALL.md pour l\'aide');
    process.exit(1);
  }
}

// Lancer les vérifications
runChecks();
