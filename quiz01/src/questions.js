/**
 * Quiz Items Configuration (SERVER-SIDE ONLY)
 * 
 * This file is NEVER sent to the client. Items are served one at a time
 * via the API, and correct answers are validated server-side.
 * 
 * Two types of items are supported:
 * 
 * 1. QUESTION ITEM:
 *    - type: 'question' (required)
 *    - question (required): The question text
 *    - questionImage (optional): Path to an image for the question (relative to /assets/)
 *    - correctSound (optional): Path to sound file played on correct answer
 *    - incorrectSound (optional): Path to sound file played on wrong answer
 *    - answers (required): Array of answer objects with:
 *        - text (required): The answer text
 *        - image (optional): Path to an image for this answer (relative to /assets/)
 *        - isCorrect (required): true if this is the correct answer
 * 
 * 2. VIDEO ITEM:
 *    - type: 'video' (required)
 *    - youtubeId (optional): The YouTube video ID (e.g., 'dQw4w9WgXcQ')
 *    - videoFile (optional): Path to local MP4 file (relative to /assets/)
 *    - title (optional): Title to display above the video
 *    NOTE: Use either youtubeId OR videoFile, not both
 * 
 * EXAMPLES:
 * 
 * Question:
 * {
 *   type: 'question',
 *   question: "What color is the sky?",
 *   questionImage: "images/sky.png",
 *   correctSound: "sounds/correct.mp3",
 *   incorrectSound: "sounds/wrong.mp3",
 *   answers: [
 *     { text: "Blue", image: null, isCorrect: true },
 *     { text: "Green", image: "images/green.png", isCorrect: false },
 *     { text: "Red", image: null, isCorrect: false }
 *   ]
 * }
 * 
 * YouTube Video:
 * {
 *   type: 'video',
 *   youtubeId: 'dQw4w9WgXcQ',
 *   title: 'Watch this before continuing!'
 * }
 * 
 * Local MP4 Video:
 * {
 *   type: 'video',
 *   videoFile: 'videos/myvideo.mp4',
 *   title: 'Check out this clip!'
 * }
 */

const quizItems = [
    {
        type: 'question',
        question: "r u ready to start the quiz?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "yes", image: null, isCorrect: true },
            { text: "no", image: null, isCorrect: false },
            { text: "i guess bro", image: null, isCorrect: false }
        ]
    },
    {
        type: 'question',
        question: "you sure?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "yes", image: null, isCorrect: true },
            { text: "no", image: null, isCorrect: false },
            { text: "yeaaahhhhhhhhhh", image: null, isCorrect: false }
        ]
    },
    {
        type: 'question',
        question: "very sure?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "no", image: null, isCorrect: false },
            { text: "yes", image: null, isCorrect: true },
            { text: "goo goo gaa gaa", image: null, isCorrect: false }
        ]
    },
    {
        type: 'question',
        question: "in the last question you will answer B ok?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "ok", image: null, isCorrect: false },
            { text: "Ok", image: null, isCorrect: false },
            { text: "okay", image: null, isCorrect: true },
            { text: "not ok", image: null, isCorrect: false }
        ]
    },
    {
        type: 'question',
        question: "whats 1 + 1",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "2 ofc!", image: null, isCorrect: false },
            { text: "11", image: null, isCorrect: true },
            { text: "I DONT NKOW", image: null, isCorrect: false },
        ]
    },
    {
        type: 'video',
        youtubeId: '9Ax56oRhcZc',
        title: 'analise the video very deeply pls'
    },
    {
        type: 'question',
        question: "what number did he say in minute 1:13:13?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "3481", image: null, isCorrect: true },
            { text: "2478", image: null, isCorrect: false },
            { text: "2376", image: null, isCorrect: false },
            { text: "idk", image: null, isCorrect: false }
        ]
    },
    {
        type: 'question',
        question: "what number did he say in minute 4:25:47?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "9967", image: null, isCorrect: false },
            { text: "10000", image: null, isCorrect: false },
            { text: "idk", image: null, isCorrect: true },
            { text: "9999", image: null, isCorrect: false }
        ]
    },
    {
        type: 'question',
        question: "is this tuff in the ctf community?",
        questionImage: "images/bigguy.jpg",
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "very tuff", image: null, isCorrect: false },
            { text: "not tuff AT ALL", image: null, isCorrect: true },
        ]
    },
    {
        type: 'video',
        youtubeId: 'igcoDFokKzU',
        title: 'video is required for next question'
    },
    {
        type: 'question',
        question: "use what you learned to solve this",
        questionImage: "images/math.avif",
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/chicken.mp3",
        answers: [
            { text: "i think it might be 12", image: null, isCorrect: false },
            { text: "it's 46 for sure", image: null, isCorrect: false },
            { text: "", image: "images/patrick.gif", isCorrect: false },
            { text: "WHAAT", image: null, isCorrect: true },
        ]
    },
    {
        type: 'question',
        question: "",
        questionImage: "images/whoishe.gif",
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "lois", image: null, isCorrect: false },
            { text: "the dog i dont remember the name lol", image: null, isCorrect: false },
            { text: "peter", image: null, isCorrect: false },
            { text: "alan", image: null, isCorrect: true },
        ]
    },
    {
        type: 'question',
        question: "are you republican or democrat? (we do care)",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "republican", image: null, isCorrect: false },
            { text: "democrat", image: null, isCorrect: false },
            { text: "", image: "images/surgeon.webp", isCorrect: true }
        ]
    },
    {
        type: 'video',
        videoFile: 'videos/minecraft.mp4',
        title: 'watch and take note for next question'
    },
    {
        type: 'question',
        question: "did you take notes?",
        questionImage: null,
        correctSound: "sounds/ding.mp3",
        incorrectSound: "sounds/buzz.mp3",
        answers: [
            { text: "yes", image: null, isCorrect: true },
            { text: "nop", image: "images/nikokado-avokado.gif", isCorrect: false },
        ]
    },
    {
        type: 'question',
        question: "the LAST question",
        questionImage: null,
        correctSound: "sounds/winner.mp3",
        incorrectSound: "sounds/chicken.mp3",
        answers: [
            { text: "C", image: null, isCorrect: false },
            { text: "A", image: null, isCorrect: true },
            { text: "B", image: null, isCorrect: false },
            { text: "D", image: null, isCorrect: false },
            { text: "not sure", image: "images/monkey.jpg", isCorrect: false }
        ]
    }
];

module.exports = quizItems;
