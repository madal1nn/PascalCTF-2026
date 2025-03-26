/**
 * Quiz Server
 * 
 * Secure server-side quiz handling. Items are never fully exposed to clients.
 * The client only receives items one at a time, without knowing which answer is correct.
 */

const express = require('express');
const path = require('path');
const quizItems = require('./questions');

const app = express();
const PORT = process.env.PORT || 3000;

// Store quiz sessions (in production, use a proper session store)
const sessions = new Map();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

/**
 * Generate a unique session ID
 */
function generateSessionId() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

/**
 * Get session or create new one
 */
function getSession(sessionId) {
    if (!sessionId || !sessions.has(sessionId)) {
        return null;
    }
    return sessions.get(sessionId);
}

/**
 * Sanitize a question item for client (remove isCorrect from answers)
 */
function sanitizeQuestion(item, index) {
    return {
        type: 'question',
        itemIndex: index,
        question: item.question,
        questionImage: item.questionImage ? `/assets/${item.questionImage}` : null,
        correctSound: item.correctSound ? `/assets/${item.correctSound}` : null,
        incorrectSound: item.incorrectSound ? `/assets/${item.incorrectSound}` : null,
        answers: item.answers.map((answer, i) => ({
            index: i,
            text: answer.text,
            image: answer.image ? `/assets/${answer.image}` : null
            // NOTE: isCorrect is NOT sent to client!
        }))
    };
}

/**
 * Sanitize a video item for client
 */
function sanitizeVideo(item, index) {
    return {
        type: 'video',
        itemIndex: index,
        youtubeId: item.youtubeId || null,
        videoFile: item.videoFile ? `/assets/${item.videoFile}` : null,
        title: item.title || null
    };
}

/**
 * Sanitize any item for client
 */
function sanitizeItem(item, index) {
    if (item.type === 'video') {
        return sanitizeVideo(item, index);
    }
    return sanitizeQuestion(item, index);
}

/**
 * Count only question items (for progress display)
 */
function countQuestions() {
    return quizItems.filter(item => item.type === 'question').length;
}

/**
 * API: Start a new quiz session
 */
app.post('/api/quiz/start', (req, res) => {
    const sessionId = generateSessionId();

    sessions.set(sessionId, {
        currentItem: 0,
        createdAt: Date.now()
    });

    const firstItem = sanitizeItem(quizItems[0], 0);

    res.json({
        sessionId,
        totalItems: quizItems.length,
        totalQuestions: countQuestions(),
        item: firstItem
    });
});

/**
 * API: Submit an answer (only valid for question items)
 */
app.post('/api/quiz/answer', (req, res) => {
    const { sessionId, answerIndex } = req.body;

    const session = getSession(sessionId);
    if (!session) {
        return res.status(400).json({ error: 'Invalid or expired session. Please restart the quiz.' });
    }

    const currentItemIndex = session.currentItem;
    const item = quizItems[currentItemIndex];

    // Ensure this is a question item
    if (item.type === 'video') {
        return res.status(400).json({ error: 'Cannot submit answer for a video item. Use skip-video endpoint.' });
    }

    if (answerIndex < 0 || answerIndex >= item.answers.length) {
        return res.status(400).json({ error: 'Invalid answer index.' });
    }

    const isCorrect = item.answers[answerIndex].isCorrect;
    const correctIndex = item.answers.findIndex(a => a.isCorrect);

    if (isCorrect) {
        // Move to next item
        session.currentItem++;

        if (session.currentItem >= quizItems.length) {
            // Quiz completed!
            sessions.delete(sessionId);
            return res.json({
                correct: true,
                correctIndex,
                completed: true,
                totalQuestions: countQuestions()
            });
        }

        // Send next item
        const nextItem = sanitizeItem(quizItems[session.currentItem], session.currentItem);
        return res.json({
            correct: true,
            correctIndex,
            completed: false,
            nextItem
        });
    } else {
        // Wrong answer - session is invalidated
        sessions.delete(sessionId);
        return res.json({
            correct: false,
            correctIndex,
            completed: false
        });
    }
});

/**
 * API: Skip a video and get the next item
 */
app.post('/api/quiz/skip-video', (req, res) => {
    const { sessionId } = req.body;

    const session = getSession(sessionId);
    if (!session) {
        return res.status(400).json({ error: 'Invalid or expired session. Please restart the quiz.' });
    }

    const currentItemIndex = session.currentItem;
    const item = quizItems[currentItemIndex];

    // Ensure this is a video item
    if (item.type !== 'video') {
        return res.status(400).json({ error: 'Current item is not a video.' });
    }

    // Move to next item
    session.currentItem++;

    if (session.currentItem >= quizItems.length) {
        // Quiz completed!
        sessions.delete(sessionId);
        return res.json({
            completed: true,
            totalQuestions: countQuestions()
        });
    }

    // Send next item
    const nextItem = sanitizeItem(quizItems[session.currentItem], session.currentItem);
    return res.json({
        completed: false,
        nextItem
    });
});

/**
 * API: Get quiz info
 */
app.get('/api/quiz/info', (req, res) => {
    res.json({
        totalItems: quizItems.length,
        totalQuestions: countQuestions()
    });
});

// Clean up old sessions every 10 minutes
setInterval(() => {
    const now = Date.now();
    const maxAge = 30 * 60 * 1000; // 30 minutes

    for (const [sessionId, session] of sessions) {
        if (now - session.createdAt > maxAge) {
            sessions.delete(sessionId);
        }
    }
}, 10 * 60 * 1000);

// Start server
app.listen(PORT, () => {
    console.log(`🎯 Quiz server running at http://localhost:${PORT}`);
    console.log(`📝 ${quizItems.length} items loaded (${countQuestions()} questions)`);
});
