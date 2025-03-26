/**
 * Quiz Client Logic
 * 
 * Meme Quiz Edition - Simple and aggressive!
 * Now with YouTube video support!
 */

class Quiz {
    constructor() {
        this.sessionId = null;
        this.totalItems = 0;
        this.totalQuestions = 0;
        this.currentItemData = null;
        this.isAnswerSelected = false;
        this.currentQuestionNumber = 0;

        // DOM Elements
        this.startScreen = document.getElementById('start-screen');
        this.loadingScreen = document.getElementById('loading-screen');
        this.quizScreen = document.getElementById('quiz-screen');
        this.videoScreen = document.getElementById('video-screen');
        this.congratsScreen = document.getElementById('congrats-screen');

        this.questionText = document.getElementById('question-text');
        this.questionImageContainer = document.getElementById('question-image-container');
        this.questionImage = document.getElementById('question-image');
        this.answersContainer = document.getElementById('answers-container');

        this.currentQuestionSpan = document.getElementById('current-question');
        this.totalQuestionsSpan = document.getElementById('total-questions');
        this.progressFill = document.getElementById('progress-fill');
        this.videoProgressFill = document.getElementById('video-progress-fill');

        // Video elements
        this.videoTitle = document.getElementById('video-title');
        this.youtubePlayer = document.getElementById('youtube-player');
        this.localVideoPlayer = document.getElementById('local-video-player');
        this.skipVideoBtn = document.getElementById('skip-video-btn');

        this.correctSound = document.getElementById('correct-sound');
        this.incorrectSound = document.getElementById('incorrect-sound');
        this.backgroundMusic = document.getElementById('background-music');

        this.startBtn = document.getElementById('start-btn');
        this.restartBtn = document.getElementById('restart-btn');

        // Initialize
        this.init();
    }

    init() {
        // Add event listeners
        this.startBtn.addEventListener('click', () => this.startQuiz());
        this.restartBtn.addEventListener('click', () => this.showStartScreen());
        this.skipVideoBtn.addEventListener('click', () => this.skipVideo());

        // Show start screen
        this.showScreen('start');
    }

    showStartScreen() {
        document.body.classList.remove('wrong-mode');
        this.stopBackgroundMusic();
        this.clearVideoPlayers();
        this.showScreen('start');
    }

    async startQuiz() {
        this.showScreen('loading');
        this.isAnswerSelected = false;
        this.currentQuestionNumber = 0;
        document.body.classList.remove('wrong-mode');

        // Start background music
        this.playBackgroundMusic();

        try {
            const response = await fetch('/api/quiz/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                throw new Error('Failed to start quiz');
            }

            const data = await response.json();

            this.sessionId = data.sessionId;
            this.totalItems = data.totalItems;
            this.totalQuestions = data.totalQuestions;
            this.currentItemData = data.item;

            // Update UI
            this.totalQuestionsSpan.textContent = this.totalQuestions;

            // Render first item
            this.renderItem();

        } catch (error) {
            console.error('Error starting quiz:', error);
            this.questionText.textContent = 'Error loading quiz. Please refresh the page.';
            this.showScreen('quiz');
        }
    }

    renderItem() {
        if (this.currentItemData.type === 'video') {
            this.renderVideo();
        } else {
            this.renderQuestion();
        }
    }

    renderQuestion() {
        const item = this.currentItemData;
        this.isAnswerSelected = false;
        this.currentQuestionNumber++;

        // Remove any wrong message from previous wrong answer
        const existingWrongMsg = document.querySelector('.wrong-message');
        if (existingWrongMsg) {
            existingWrongMsg.remove();
        }

        // Update progress
        this.currentQuestionSpan.textContent = this.currentQuestionNumber;
        const progressPercent = ((this.currentQuestionNumber - 1) / this.totalQuestions) * 100;
        this.progressFill.style.width = `${progressPercent}%`;

        // Set question text
        this.questionText.textContent = item.question;

        // Handle question image
        if (item.questionImage) {
            this.questionImage.src = item.questionImage;
            this.questionImageContainer.classList.remove('hidden');
        } else {
            this.questionImageContainer.classList.add('hidden');
        }

        // Load sounds for this question
        if (item.correctSound) {
            this.correctSound.src = item.correctSound;
        }
        if (item.incorrectSound) {
            this.incorrectSound.src = item.incorrectSound;
        }

        // Generate answer buttons
        this.generateAnswers(item.answers);

        // Show quiz screen
        this.showScreen('quiz');
    }

    renderVideo() {
        const item = this.currentItemData;

        // Set video title
        this.videoTitle.textContent = item.title || 'Video Break';

        // Clear both players first
        this.clearVideoPlayers();

        // Show the appropriate player
        if (item.youtubeId) {
            // YouTube video
            this.youtubePlayer.style.display = 'block';
            this.localVideoPlayer.style.display = 'none';
            this.youtubePlayer.src = `https://www.youtube.com/embed/${item.youtubeId}?autoplay=1`;
        } else if (item.videoFile) {
            // Local MP4 video
            this.youtubePlayer.style.display = 'none';
            this.localVideoPlayer.style.display = 'block';
            this.localVideoPlayer.src = item.videoFile;
            this.localVideoPlayer.play().catch(() => console.log('Could not autoplay local video'));
        }

        // Update progress bar (use current position in total items)
        const progressPercent = (item.itemIndex / this.totalItems) * 100;
        this.videoProgressFill.style.width = `${progressPercent}%`;

        // Show video screen
        this.showScreen('video');
    }

    clearVideoPlayers() {
        this.youtubePlayer.src = '';
        this.localVideoPlayer.pause();
        this.localVideoPlayer.src = '';
    }

    generateAnswers(answers) {
        const letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
        this.answersContainer.innerHTML = '';

        answers.forEach((answer, index) => {
            const button = document.createElement('button');
            button.className = 'answer-button';
            button.setAttribute('data-index', index);

            // Create answer letter
            const letterSpan = document.createElement('span');
            letterSpan.className = 'answer-letter';
            letterSpan.textContent = letters[index] || (index + 1);

            // Create answer content container
            const contentDiv = document.createElement('div');
            contentDiv.className = 'answer-content';

            // Add image if present
            if (answer.image) {
                const img = document.createElement('img');
                img.src = answer.image;
                img.alt = answer.text;
                img.className = 'answer-image';
                contentDiv.appendChild(img);
            }

            // Add text
            const textSpan = document.createElement('span');
            textSpan.className = 'answer-text';
            textSpan.textContent = answer.text;
            contentDiv.appendChild(textSpan);

            // Assemble button
            button.appendChild(letterSpan);
            button.appendChild(contentDiv);

            // Add click handler
            button.addEventListener('click', () => this.selectAnswer(index));

            this.answersContainer.appendChild(button);
        });
    }

    async selectAnswer(answerIndex) {
        if (this.isAnswerSelected) return;
        this.isAnswerSelected = true;

        const buttons = this.answersContainer.querySelectorAll('.answer-button');

        // Disable all buttons immediately
        buttons.forEach(btn => btn.classList.add('disabled'));

        try {
            const response = await fetch('/api/quiz/answer', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sessionId: this.sessionId,
                    answerIndex
                })
            });

            if (!response.ok) {
                throw new Error('Failed to submit answer');
            }

            const result = await response.json();

            if (result.correct) {
                // Immediately show green
                buttons[answerIndex].classList.add('correct');

                // Play correct sound
                if (this.currentItemData.correctSound) {
                    this.playSound(this.correctSound);
                }

                // Move to next item after brief moment
                setTimeout(() => {
                    if (result.completed) {
                        this.showCongratulations();
                    } else {
                        this.currentItemData = result.nextItem;
                        this.renderItem();
                    }
                }, 800);

            } else {
                // WRONG ANSWER - AGGRESSIVE MODE!

                // Immediately show red on clicked button
                buttons[answerIndex].classList.add('wrong');

                // Turn EVERYTHING red
                document.body.classList.add('wrong-mode');

                // Play wrong sound
                if (this.currentItemData.incorrectSound) {
                    this.playSound(this.incorrectSound);
                }

                // Add wrong message
                const wrongMsg = document.createElement('div');
                wrongMsg.className = 'wrong-message';
                wrongMsg.textContent = 'WRONG!';
                this.answersContainer.appendChild(wrongMsg);

                // Auto restart after 1 seconds - no option to go back!
                setTimeout(() => {
                    document.body.classList.remove('wrong-mode');
                    this.showStartScreen();
                }, 1000);
            }

        } catch (error) {
            console.error('Error submitting answer:', error);
            // Re-enable buttons on error
            buttons.forEach(btn => btn.classList.remove('disabled'));
            this.isAnswerSelected = false;
        }
    }

    async skipVideo() {
        try {
            const response = await fetch('/api/quiz/skip-video', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sessionId: this.sessionId
                })
            });

            if (!response.ok) {
                throw new Error('Failed to skip video');
            }

            const result = await response.json();

            // Clear the video players
            this.clearVideoPlayers();

            if (result.completed) {
                this.showCongratulations();
            } else {
                this.currentItemData = result.nextItem;
                this.renderItem();
            }

        } catch (error) {
            console.error('Error skipping video:', error);
        }
    }

    playSound(audioElement) {
        audioElement.currentTime = 0;
        audioElement.play().catch(() => {
            console.log('Could not play sound');
        });
    }

    playBackgroundMusic() {
        this.backgroundMusic.volume = 0.3;
        this.backgroundMusic.currentTime = 0;
        this.backgroundMusic.play().catch(() => {
            console.log('Could not play background music');
        });
    }

    stopBackgroundMusic() {
        this.backgroundMusic.pause();
        this.backgroundMusic.currentTime = 0;
    }

    showScreen(screen) {
        this.startScreen.classList.add('hidden');
        this.loadingScreen.classList.add('hidden');
        this.quizScreen.classList.add('hidden');
        this.videoScreen.classList.add('hidden');
        this.congratsScreen.classList.add('hidden');

        switch (screen) {
            case 'start':
                this.startScreen.classList.remove('hidden');
                break;
            case 'loading':
                this.loadingScreen.classList.remove('hidden');
                break;
            case 'quiz':
                this.quizScreen.classList.remove('hidden');
                break;
            case 'video':
                this.videoScreen.classList.remove('hidden');
                break;
            case 'congrats':
                this.congratsScreen.classList.remove('hidden');
                break;
        }
    }

    showCongratulations() {
        this.progressFill.style.width = '100%';
        this.clearVideoPlayers();
        this.showScreen('congrats');
    }
}

// Initialize quiz when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new Quiz();
});
