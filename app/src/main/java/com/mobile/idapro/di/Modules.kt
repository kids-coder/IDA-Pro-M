package com.mobile.idapro.di

import android.content.Context
import androidx.room.Room
import com.mobile.idapro.data.local.*
import com.mobile.idapro.data.repository.*
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * IDA Pro M - Dependency Injection Module
 * 
 * Provides database, repository, and utility instances via Hilt.
 */

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    
    /**
     * Provide Room database instance.
     */
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase {
        return Room.databaseBuilder(
            context.applicationContext,
            AppDatabase::class.java,
            AppDatabase.DATABASE_NAME
        )
        .fallbackToDestructiveMigration()  // For development; use proper migrations in production
        .build()
    }
    
    @Provides
    fun provideLoadedFileDao(database: AppDatabase): LoadedFileDao = database.loadedFileDao()
    
    @Provides
    fun provideAnalysisResultDao(database: AppDatabase): AnalysisResultDao = database.analysisResultDao()
    
    @Provides
    fun provideFunctionDao(database: AppDatabase): FunctionDao = database.functionDao()
    
    @Provides
    fun provideStringEntryDao(database: AppDatabase): StringEntryDao = database.stringEntryDao()
    
    @Provides
    fun provideUserSettingsDao(database: AppDatabase): UserSettingsDao = database.userSettingsDao()
}

/**
 * Repository module for providing data access instances.
 */
@Module
@InstallIn(SingletonComponent::class)
object RepositoryModule {
    
    @Provides
    @Singleton
    fun provideFileRepository(
        fileDao: LoadedFileDao,
        analysisResultDao: AnalysisResultDao,
        functionDao: FunctionDao,
        stringEntryDao: StringEntryDao
    ): FileRepository {
        return FileRepository(fileDao, analysisResultDao, functionDao, stringEntryDao)
    }
    
    @Provides
    @Singleton
    fun provideAnalysisRepository(
        analysisResultDao: AnalysisResultDao,
        functionDao: FunctionDao,
        stringEntryDao: StringEntryDao
    ): AnalysisRepository {
        return AnalysisRepository(analysisResultDao, functionDao, stringEntryDao)
    }
    
    @Provides
    @Singleton
    fun provideSettingsRepository(settingsDao: UserSettingsDao): SettingsRepository {
        return SettingsRepository(settingsDao)
    }
}

/**
 * Utility module for providing helper classes.
 */
@Module
@InstallIn(SingletonComponent::class)
object UtilModule {
    
    // Add any utility providers here as needed
}
